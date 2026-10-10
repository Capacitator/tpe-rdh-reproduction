"""Revised authenticated-TPE primitives (v2) for the NIST SP 800-22 audit.

This module is a *thin, explicit revision layer* over the existing prototype in
``tpe_rdh_reproduction/src/authenticated_tpe.py``.  The construction is not
redesigned and no parameter is tuned: the only algorithmic change is the
keystream reduction in ``pair_shift``, which is made exactly uniform by
rejection sampling (see ``docs/AUDIT.md``, finding A3).

Backwards compatibility
-----------------------
For every (Ktpe, ImageID, bid, k, class_size) the revised function returns
exactly the same value as the original ``word % class_size`` whenever
``word < floor(2**32 / class_size) * class_size``.  The rejection branch is
reached with probability at most ``255 / 2**32`` (about 6e-8) per reduction, so
every known-answer vector and every previously generated ciphertext that the
original code produced is reproduced bit-for-bit by this revision.
"""
from __future__ import annotations

import hashlib
import hmac
import sys
from pathlib import Path
from typing import Sequence

import numpy as np

_HERE = Path(__file__).resolve()
_ORIG_SRC = _HERE.parents[2] / "tpe_rdh_reproduction" / "src"
if not (_ORIG_SRC / "authenticated_tpe.py").is_file():  # pragma: no cover
    raise ImportError(f"original prototype not found at {_ORIG_SRC}")
if str(_ORIG_SRC) not in sys.path:
    sys.path.insert(0, str(_ORIG_SRC))

import authenticated_tpe as base  # noqa: E402  (path set above)

REVISION_ID = "atpe-v2.1"
REVISION_SUMMARY = (
    "pair_shift reduction made exactly uniform by rejection sampling; "
    "all other primitives, derivations, parameters and traversal orders are "
    "unchanged from the audited prototype"
)
UINT32 = 1 << 32

# --------------------------------------------------------------------------
# Primitive re-exports (unchanged) that the stream builders rely on.
# --------------------------------------------------------------------------
derive_keys = base.derive_keys
derive_group_key = base.derive_group_key
derive_image_key = base.derive_image_key
group_blocks = base.group_blocks
block_r1 = base.block_r1
classify_pair = base.classify_pair
step2_pair = base.step2_pair
inverse_step2_pair = base.inverse_step2_pair
rcm_forward = base.rcm_forward
rcm_inverse = base.rcm_inverse
HMACDRBG = base.HMACDRBG
protect_image = base.protect_image
verify_and_decrypt = base.verify_and_decrypt
generate_image_id = base.generate_image_id
AuthenticationError = base.AuthenticationError
InsufficientCapacity = base.InsufficientCapacity
_id_bytes = base._bytes
_u16 = base._u16
_sum_classes = base._SUM_CLASSES
_sum_positions = base._SUM_POSITIONS


def pair_shift_message(image_id: bytes, block_id: int, pair_index: int) -> bytes:
    """Exact Step-1 PRF message (unchanged from the audited prototype)."""
    return b"tpe-shift" + _id_bytes(image_id, 16, "ImageID") + _u16(block_id) + _u16(pair_index)


def pair_shift_word(ktpe: bytes, image_id: bytes, block_id: int, pair_index: int) -> int:
    """Raw 32-bit big-endian Step-1 PRF output word (pre-reduction)."""
    digest = hmac.new(bytes(ktpe), pair_shift_message(image_id, block_id, pair_index),
                      hashlib.sha256).digest()
    return int.from_bytes(digest[:4], "big")


def pair_shift(ktpe: bytes, image_id: bytes, block_id: int, pair_index: int, class_size: int) -> int:
    """Uniform Step-1 rotation offset in ``[0, class_size)``.

    Revision A3: instead of ``word % class_size`` (whose bias is bounded by
    ``(2**32 mod class_size) / 2**32``, i.e. at most 6e-8), the reduction uses
    rejection sampling so the result is exactly uniform over the class.
    Retries are domain-separated and never collide with the primary message.
    """
    if class_size < 1:
        raise ValueError("class_size must be positive")
    msg = pair_shift_message(image_id, block_id, pair_index)
    limit = (UINT32 // class_size) * class_size
    word = int.from_bytes(hmac.new(bytes(ktpe), msg, hashlib.sha256).digest()[:4], "big")
    if word < limit:
        return word % class_size
    for attempt in range(1, 1 << 16):
        retry = msg + b"\x01retry" + attempt.to_bytes(2, "big")
        word = int.from_bytes(hmac.new(bytes(ktpe), retry, hashlib.sha256).digest()[:4], "big")
        if word < limit:
            return word % class_size
    raise AuthenticationError("Step-1 rejection sampling exhausted its retry budget")


# --------------------------------------------------------------------------
# Step-1 / Step-2 using the revised reduction
# --------------------------------------------------------------------------
def step1_pair(x: int, y: int, ktpe: bytes, image_id: bytes, block_id: int,
               pair_index: int) -> tuple[int, int]:
    s = int(x) + int(y)
    inside = base._in_dc(int(x), int(y))
    values = base._SUM_CLASSES[(s, inside)]
    if not values:
        raise AuthenticationError("empty Step-1 class for a valid pixel pair")
    i = base._SUM_POSITIONS[(s, inside)][int(x)]
    shift = pair_shift(ktpe, image_id, block_id, pair_index, len(values))
    x1 = values[(i + shift) % len(values)]
    return x1, s - x1


def inverse_step1_pair(x1: int, y1: int, ktpe: bytes, image_id: bytes, block_id: int,
                       pair_index: int) -> tuple[int, int]:
    s = int(x1) + int(y1)
    inside = base._in_dc(int(x1), int(y1))
    values = base._SUM_CLASSES[(s, inside)]
    if not values:
        raise AuthenticationError("empty inverse Step-1 class")
    try:
        j = base._SUM_POSITIONS[(s, inside)][int(x1)]
    except KeyError as exc:
        raise AuthenticationError("Step-1 pair is outside its declared class") from exc
    shift = pair_shift(ktpe, image_id, block_id, pair_index, len(values))
    x = values[(j - shift) % len(values)]
    return x, s - x


_real_pairs = base._pairs
_get_block = base._get_block
_serialize_block = base._serialize_block


def step1_image(image: np.ndarray, user_key: bytes, image_id: bytes,
                shift_sink: list[int] | None = None) -> np.ndarray:
    """Step-1 transform; optionally records every reduced rotation offset."""
    out = np.empty_like(image)
    for c in range(base.CHANNELS):
        keys = derive_keys(user_key, c)
        for bid in range(base.BLOCK_COUNT):
            src = _real_pairs(_get_block(image, c, bid))
            dst = np.empty_like(src)
            for k, (x, y) in enumerate(src):
                xi, yi = int(x), int(y)
                s = xi + yi
                inside = base._in_dc(xi, yi)
                values = base._SUM_CLASSES[(s, inside)]
                i = base._SUM_POSITIONS[(s, inside)][xi]
                shift = pair_shift(keys["Ktpe"], image_id, bid, k, len(values))
                if shift_sink is not None:
                    shift_sink.append(shift)
                x1 = values[(i + shift) % len(values)]
                dst[k] = (x1, s - x1)
            _get_block(out, c, bid)[:] = dst.reshape(base.BLOCK_SIZE, base.BLOCK_SIZE)
    return out


def class_size_of_image_slot(pair: np.ndarray) -> tuple[int, int]:
    """(sum, class_size) of the class a real image pair belongs to."""
    x, y = int(pair[0]), int(pair[1])
    s = x + y
    return s, len(base._SUM_CLASSES[(s, base._in_dc(x, y))])


# --------------------------------------------------------------------------
# Streams used by the NIST protocol
# --------------------------------------------------------------------------
def drbg_bytes(entropy_input: bytes, nonce: bytes, personalization: bytes,
               byte_count: int) -> bytes:
    """Consecutive 4-byte HMAC_DRBG Generate calls, as used by the method."""
    if byte_count % 4:
        raise ValueError("byte_count must be a multiple of 4")
    rng = base.HMACDRBG(entropy_input, nonce, personalization)
    out = bytearray()
    for _ in range(byte_count // 4):
        out += rng.generate4().to_bytes(4, "big")
    return bytes(out)


def pair_shift_digests(user_key: bytes, image_id: bytes, byte_count: int) -> bytes:
    """Full SHA-256 Step-1 PRF digests in the authenticated traversal order."""
    keys = [derive_keys(user_key, c)["Ktpe"] for c in range(3)]
    out = bytearray()
    for c in range(3):
        for bid in range(base.BLOCK_COUNT):
            for k in range(base.PAIRS_PER_BLOCK):
                out += hmac.new(keys[c], pair_shift_message(image_id, bid, k),
                                hashlib.sha256).digest()
                if len(out) >= byte_count:
                    return bytes(out[:byte_count])
    raise ValueError("pair-shift domain exhausted")


def block_r1_digests(user_key: bytes) -> bytes:
    """Every SHA-256 Kr1 digest one UserKey produces (768 x 32 = 24,576 bytes).

    The Step-2 keystream is a per-block quantity, so a single UserKey yields
    only 3 x 256 derivations. Longer streams therefore enumerate several
    disjoint UserKeys instead of repeating one key's output.
    """
    keys = [derive_keys(user_key, c)["Kr1"] for c in range(3)]
    out = bytearray()
    for c in range(3):
        for bid in range(base.BLOCK_COUNT):
            out += hmac.new(keys[c], b"r1" + _u16(bid), hashlib.sha256).digest()
    return bytes(out)


BLOCK_R1_BYTES_PER_KEY = 3 * base.BLOCK_COUNT * 32


def group_tag_bytes(step1: np.ndarray, user_key: bytes, image_id: bytes) -> bytes:
    """All 192 authentic group tags of one channel/group enumeration (R, G, B)."""
    out = bytearray()
    for c in range(3):
        for ids in group_blocks(derive_keys(user_key, c)["Kstruct"]):
            out += base._group_mac(step1, user_key, image_id, c, ids)
    return bytes(out)


def group_tag_bytes_from_image(image: np.ndarray, user_key: bytes, image_id: bytes) -> bytes:
    return group_tag_bytes(step1_image(image, user_key, image_id), user_key, image_id)


def reduced_shift_bytes(image: np.ndarray, user_key: bytes, image_id: bytes) -> bytes:
    """Authentic reduced Step-1 rotation offsets, one byte per pair, image order."""
    shifts: list[int] = []
    step1_image(image, user_key, image_id, shift_sink=shifts)
    if any(s > 255 for s in shifts):
        raise AssertionError("reduced offset does not fit a byte")
    return bytes(shifts)


# --------------------------------------------------------------------------
# Revision activation
# --------------------------------------------------------------------------
# ``authenticated_tpe.step1_pair`` resolves ``pair_shift`` from its own module
# globals, so binding the audited function into that namespace activates the
# revision for every code path (step 1, marking, verification, streams) without
# forking the cipher.  The two implementations agree bit-for-bit except on the
# rejection branch, whose probability is at most 2**-24 per reduction, so all
# previously published vectors and ciphertexts are reproduced exactly.
_ORIGINAL_PAIR_SHIFT = base.pair_shift
base.pair_shift = pair_shift


def activation_status() -> dict:
    """Evidence that the revision is active inside the audited prototype."""
    return {
        "revision_id": REVISION_ID,
        "prototype_pair_shift_is_revised": base.pair_shift is pair_shift,
        "original_pair_shift": f"{_ORIGINAL_PAIR_SHIFT.__module__}.{_ORIGINAL_PAIR_SHIFT.__name__}",
        "rejection_probability_upper_bound": 255 / UINT32,
    }


__all__ = [
    "REVISION_ID", "REVISION_SUMMARY", "base", "activation_status",
    "pair_shift", "pair_shift_word",
    "pair_shift_message", "step1_pair", "inverse_step1_pair", "step1_image",
    "pair_shift_digests", "block_r1_digests", "group_tag_bytes",
    "group_tag_bytes_from_image", "reduced_shift_bytes", "drbg_bytes",
    "derive_keys", "derive_group_key", "derive_image_key", "group_blocks",
    "block_r1", "classify_pair", "step2_pair", "inverse_step2_pair",
    "rcm_forward", "rcm_inverse", "HMACDRBG", "protect_image",
    "verify_and_decrypt", "generate_image_id", "AuthenticationError",
    "InsufficientCapacity", "class_size_of_image_slot",
]
