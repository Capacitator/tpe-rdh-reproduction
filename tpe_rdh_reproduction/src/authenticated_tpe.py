"""Paper-specific reversible block-group authentication prototype.

This module is deliberately separate from the existing chaotic TPE/RDH pipeline.
It implements the method in ``docs/reference/Our method.pdf`` plus explicit
byte-level conventions requested for the reproduction. It is a research
prototype, not a production encryption library.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets
from typing import Iterable, Sequence

import numpy as np

IMAGE_SIZE = 512
BLOCK_SIZE = 32
BLOCKS_PER_AXIS = IMAGE_SIZE // BLOCK_SIZE
BLOCK_COUNT = BLOCKS_PER_AXIS**2
PAIRS_PER_BLOCK = BLOCK_SIZE * BLOCK_SIZE // 2
GROUP_SIZE = 4
GROUPS_PER_CHANNEL = BLOCK_COUNT // GROUP_SIZE
TAG_BITS = 256
CHANNELS = 3
CHANNEL_LABELS = (b"R", b"G", b"B")
MAX_PIXEL = 255


class AuthenticationError(ValueError):
    """Raised when an operation cannot safely complete."""


class InsufficientCapacity(AuthenticationError):
    """Raised when even whole-image mode cannot embed its tag."""


def _bytes(value: bytes, length: int, name: str) -> bytes:
    value = bytes(value)
    if len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return value


def _u16(value: int) -> bytes:
    if not 0 <= int(value) <= 0xFFFF:
        raise ValueError("integer does not fit uint16")
    return int(value).to_bytes(2, "big")


def generate_image_id() -> bytes:
    """Generate a fresh private 128-bit ImageID using the OS CSPRNG."""
    return secrets.token_bytes(16)


def derive_keys(user_key: bytes, channel: int | None = None) -> dict[str, bytes]:
    """Derive paper keys; pass a channel (0,1,2) for its per-channel keys."""
    key = bytes(user_key)
    if not key:
        raise ValueError("UserKey must not be empty")
    kauth = hmac.new(key, b"auth", hashlib.sha256).digest()
    result = {"Kauth": kauth, "Kimage_root": hmac.new(kauth, b"image", hashlib.sha256).digest()}
    if channel is None:
        return result
    if channel not in (0, 1, 2):
        raise ValueError("channel must be 0, 1, or 2")
    c = bytes((channel,))
    kch = hmac.new(key, b"channel" + c, hashlib.sha256).digest()
    result.update({
        "Kch": kch,
        "Ktpe": hmac.new(kch, b"tpe", hashlib.sha256).digest(),
        "Kr1": hmac.new(kch, b"r1", hashlib.sha256).digest(),
        "Kstruct": hmac.new(kch, b"struct", hashlib.sha256).digest(),
    })
    return result


def derive_group_key(kauth: bytes, image_id: bytes, channel: int, block_ids: Sequence[int]) -> bytes:
    image_id = _bytes(image_id, 16, "ImageID")
    if channel not in (0, 1, 2) or len(block_ids) != 4:
        raise ValueError("group key needs a channel and exactly four ordered block IDs")
    msg = image_id + bytes((channel,)) + b"".join(_u16(bid) for bid in block_ids)
    return hmac.new(bytes(kauth), msg, hashlib.sha256).digest()


def derive_image_key(kauth: bytes, image_id: bytes) -> bytes:
    return hmac.new(bytes(kauth), b"image" + _bytes(image_id, 16, "ImageID"), hashlib.sha256).digest()


def pair_shift(ktpe: bytes, image_id: bytes, block_id: int, pair_index: int, class_size: int) -> int:
    if class_size < 1:
        raise ValueError("class_size must be positive")
    msg = b"tpe-shift" + _bytes(image_id, 16, "ImageID") + _u16(block_id) + _u16(pair_index)
    word = int.from_bytes(hmac.new(bytes(ktpe), msg, hashlib.sha256).digest()[:4], "big")
    return word % class_size


def block_r1(kr1: bytes, block_id: int) -> int:
    digest = hmac.new(bytes(kr1), b"r1" + _u16(block_id), hashlib.sha256).digest()
    return int.from_bytes(digest[:4], "big") % 4


def rcm_forward(x: int, y: int) -> tuple[int, int]:
    return 2 * int(x) - int(y), 2 * int(y) - int(x)


def rcm_inverse(xp: int, yp: int) -> tuple[int, int]:
    # Exact integer ceiling, including negative numerators.
    return -(-(2 * int(xp) + int(yp)) // 3), -(-(int(xp) + 2 * int(yp)) // 3)


def _in_dc(x: int, y: int) -> bool:
    xp, yp = rcm_forward(x, y)
    if not (0 <= xp <= 255 and 0 <= yp <= 255):
        return False
    return not ((x & 1) and (y & 1) and (xp in (1, 255) or yp in (1, 255)))


def classify_pair(x: int, y: int) -> str:
    """Return paper's T/O/N class for an 8-bit input pair."""
    if not (0 <= x <= 255 and 0 <= y <= 255):
        raise ValueError("pixels must be uint8 values")
    if not _in_dc(x, y):
        return "N"
    return "O" if (x & 1) and (y & 1) else "T"


def _pair_classes_by_sum() -> dict[tuple[int, bool], tuple[int, ...]]:
    table: dict[tuple[int, bool], tuple[int, ...]] = {}
    for s in range(511):
        lo, hi = max(0, s - 255), min(255, s)
        inside = tuple(x for x in range(lo, hi + 1) if _in_dc(x, s - x))
        outside = tuple(x for x in range(lo, hi + 1) if not _in_dc(x, s - x))
        table[(s, True)] = inside
        table[(s, False)] = outside
    return table


_SUM_CLASSES = _pair_classes_by_sum()
_SUM_POSITIONS = {key: {value: i for i, value in enumerate(values)} for key, values in _SUM_CLASSES.items()}


def step1_pair(x: int, y: int, ktpe: bytes, image_id: bytes, block_id: int, pair_index: int) -> tuple[int, int]:
    s = int(x) + int(y)
    inside = _in_dc(int(x), int(y))
    values = _SUM_CLASSES[(s, inside)]
    if not values:
        raise AuthenticationError("empty Step-1 class for a valid pixel pair")
    i = _SUM_POSITIONS[(s, inside)][int(x)]
    shift = pair_shift(ktpe, image_id, block_id, pair_index, len(values))
    x1 = values[(i + shift) % len(values)]
    return x1, s - x1


def inverse_step1_pair(x1: int, y1: int, ktpe: bytes, image_id: bytes, block_id: int, pair_index: int) -> tuple[int, int]:
    s = int(x1) + int(y1)
    inside = _in_dc(int(x1), int(y1))
    values = _SUM_CLASSES[(s, inside)]
    if not values:
        raise AuthenticationError("empty inverse Step-1 class")
    try:
        j = _SUM_POSITIONS[(s, inside)][int(x1)]
    except ValueError as exc:
        raise AuthenticationError("Step-1 pair is outside its declared class") from exc
    shift = pair_shift(ktpe, image_id, block_id, pair_index, len(values))
    x = values[(j - shift) % len(values)]
    return x, s - x


def step2_pair(x: int, y: int, r1: int) -> tuple[int, int]:
    if not 0 <= r1 <= 3:
        raise ValueError("r1 must be in 0..3")
    if x < y:
        return (x + r1) % y, y
    if y < x:
        return x, (y + r1) % x
    return x, y


def inverse_step2_pair(x2: int, y2: int, r1: int) -> tuple[int, int]:
    if not 0 <= r1 <= 3:
        raise ValueError("r1 must be in 0..3")
    if x2 < y2:
        return (x2 - r1) % y2, y2
    if y2 < x2:
        return x2, (y2 - r1) % x2
    return x2, y2


class HMACDRBG:
    """The HMAC_DRBG instantiation and 4-byte Generate calls in the paper."""
    def __init__(self, entropy_input: bytes, nonce: bytes = b"", personalization_string: bytes = b"group-perm"):
        self.k = bytes(32)
        self.v = bytes([1]) * 32
        self.update(bytes(entropy_input) + bytes(nonce) + bytes(personalization_string))

    def update(self, data: bytes = b"") -> None:
        self.k = hmac.new(self.k, self.v + b"\x00" + data, hashlib.sha256).digest()
        self.v = hmac.new(self.k, self.v, hashlib.sha256).digest()
        if data:
            self.k = hmac.new(self.k, self.v + b"\x01" + data, hashlib.sha256).digest()
            self.v = hmac.new(self.k, self.v, hashlib.sha256).digest()

    def generate4(self) -> int:
        self.v = hmac.new(self.k, self.v, hashlib.sha256).digest()
        result = int.from_bytes(self.v[:4], "big")
        self.update(b"")
        return result


def group_blocks(kstruct: bytes) -> tuple[tuple[int, int, int, int], ...]:
    rng = HMACDRBG(_bytes(kstruct, 32, "Kstruct"), b"", b"group-perm")
    perm = list(range(BLOCK_COUNT))
    for i in range(BLOCK_COUNT - 1, 0, -1):
        limit = ((1 << 32) // (i + 1)) * (i + 1)
        x = rng.generate4()
        while x >= limit:
            x = rng.generate4()
        j = x % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return tuple(tuple(perm[g:g + GROUP_SIZE]) for g in range(0, BLOCK_COUNT, GROUP_SIZE))  # type: ignore[return-value]


def _validate_image(image: np.ndarray) -> np.ndarray:
    a = np.asarray(image)
    if a.shape != (IMAGE_SIZE, IMAGE_SIZE, CHANNELS) or a.dtype != np.uint8:
        raise ValueError("image must be 512x512x3 uint8 RGB")
    return np.ascontiguousarray(a)


def _get_block(image: np.ndarray, c: int, bid: int) -> np.ndarray:
    by, bx = divmod(bid, BLOCKS_PER_AXIS)
    return image[by * BLOCK_SIZE:(by + 1) * BLOCK_SIZE, bx * BLOCK_SIZE:(bx + 1) * BLOCK_SIZE, c]


def _pairs(block: np.ndarray) -> np.ndarray:
    return np.asarray(block).reshape(-1).reshape(PAIRS_PER_BLOCK, 2)


def _step1_image(image: np.ndarray, user_key: bytes, image_id: bytes) -> np.ndarray:
    out = np.empty_like(image)
    for c in range(CHANNELS):
        keys = derive_keys(user_key, c)
        for bid in range(BLOCK_COUNT):
            src = _pairs(_get_block(image, c, bid))
            dst = np.empty_like(src)
            for k, (x, y) in enumerate(src):
                dst[k] = step1_pair(int(x), int(y), keys["Ktpe"], image_id, bid, k)
            _get_block(out, c, bid)[:] = dst.reshape(BLOCK_SIZE, BLOCK_SIZE)
    return out


def _step2_image(image: np.ndarray, user_key: bytes) -> np.ndarray:
    out = np.empty_like(image)
    for c in range(CHANNELS):
        keys = derive_keys(user_key, c)
        for bid in range(BLOCK_COUNT):
            src = _pairs(_get_block(image, c, bid)); dst = np.empty_like(src)
            r1 = block_r1(keys["Kr1"], bid)
            for k, (x, y) in enumerate(src):
                dst[k] = step2_pair(int(x), int(y), r1)
            _get_block(out, c, bid)[:] = dst.reshape(BLOCK_SIZE, BLOCK_SIZE)
    return out


def _transform_image(image: np.ndarray, user_key: bytes, image_id: bytes, inverse: bool = False) -> np.ndarray:
    if not inverse:
        return _step2_image(_step1_image(image, user_key, image_id), user_key)
    out = np.empty_like(image)
    for c in range(CHANNELS):
        keys = derive_keys(user_key, c)
        for bid in range(BLOCK_COUNT):
            src = _pairs(_get_block(image, c, bid)); dst = np.empty_like(src)
            r1 = block_r1(keys["Kr1"], bid)
            for k, (x, y) in enumerate(src):
                x1, y1 = inverse_step2_pair(int(x), int(y), r1)
                dst[k] = inverse_step1_pair(x1, y1, keys["Ktpe"], image_id, bid, k)
            _get_block(out, c, bid)[:] = dst.reshape(BLOCK_SIZE, BLOCK_SIZE)
    return out


def _serialize_block(image: np.ndarray, c: int, bid: int) -> bytes:
    return _get_block(image, c, bid).tobytes(order="C")


def _group_mac(step1: np.ndarray, user_key: bytes, image_id: bytes, c: int, block_ids: Sequence[int]) -> bytes:
    keys = derive_keys(user_key)
    key = derive_group_key(keys["Kauth"], image_id, c, block_ids)
    message = b"".join(_serialize_block(step1, c, b) for b in block_ids)
    message += image_id + b"".join(_u16(b) for b in block_ids)
    return hmac.new(key, message, hashlib.sha256).digest()


def _image_mac(step1: np.ndarray, user_key: bytes, image_id: bytes) -> bytes:
    key = derive_image_key(derive_keys(user_key)["Kauth"], image_id)
    message = b"".join(_serialize_block(step1, c, bid) for c in range(CHANNELS) for bid in range(BLOCK_COUNT)) + image_id
    return hmac.new(key, message, hashlib.sha256).digest()


def _tag_bits(tag: bytes) -> list[int]:
    return [(b >> shift) & 1 for b in tag for shift in range(7, -1, -1)]


def _bits_tag(bits: Sequence[int]) -> bytes:
    if len(bits) != TAG_BITS:
        raise AuthenticationError("extracted tag has wrong bit length")
    return bytes(sum(int(bits[i + j]) << (7 - j) for j in range(8)) for i in range(0, TAG_BITS, 8))


def _embed_pairs(image: np.ndarray, c_and_bid_pairs: Sequence[tuple[int, int, int]], tag: bytes) -> tuple[bool, int, int]:
    """Embed in ordered (channel, block_id, pair_index) slots, returning success, slots, net."""
    plan: list[tuple[int, int, int, str, int]] = []
    net = 0
    n_count = 0
    for c, bid, k in c_and_bid_pairs:
        pair = _pairs(_get_block(image, c, bid))[k]
        x, y = int(pair[0]), int(pair[1])
        kind = classify_pair(x, y)
        saved = x & 1 if kind == "N" else 0
        plan.append((c, bid, k, kind, saved))
        if kind == "N":
            net -= 1
            n_count += 1
        else:
            net += 1
        if net >= TAG_BITS:
            break
    if net < TAG_BITS:
        return False, len(plan), net
    stream = _tag_bits(tag) + [item[4] for item in plan if item[3] == "N"]
    cursor = 0
    for c, bid, k, kind, _saved in plan:
        block_pairs = _pairs(_get_block(image, c, bid))
        x, y = map(int, block_pairs[k])
        if kind == "T":
            xp, yp = rcm_forward(x, y)
            block_pairs[k] = ((xp & ~1) | 1, (yp & ~1) | stream[cursor])
            cursor += 1
        elif kind == "O":
            block_pairs[k] = (x & ~1, (y & ~1) | stream[cursor])
            cursor += 1
        else:
            block_pairs[k, 0] = x & ~1
        _get_block(image, c, bid)[:] = block_pairs.reshape(BLOCK_SIZE, BLOCK_SIZE)
    if cursor != TAG_BITS + n_count:
        raise AssertionError("RCM stream consumption disagrees with net capacity")
    return True, len(plan), net


def _extract_pairs(image: np.ndarray, slots: Sequence[tuple[int, int, int]]) -> tuple[bytes, int, list[tuple[int, int, int]]] | None:
    bits: list[int] = []
    n_slots: list[tuple[int, int, int]] = []
    for c, bid, k in slots:
        block_pairs = _pairs(_get_block(image, c, bid))
        xp, yp = map(int, block_pairs[k])
        if xp & 1:
            bits.append(yp & 1)
            x0, y0 = xp & ~1, yp & ~1
            x, y = rcm_inverse(x0, y0)
            if not (0 <= x <= 255 and 0 <= y <= 255):
                return None
            block_pairs[k] = (x, y)
        elif _in_dc(xp | 1, yp | 1):
            bits.append(yp & 1)
            block_pairs[k] = (xp | 1, yp | 1)
        else:
            n_slots.append((c, bid, k))
            # N's original x LSB is carried after the tag and other saved bits.
        _get_block(image, c, bid)[:] = block_pairs.reshape(BLOCK_SIZE, BLOCK_SIZE)
        if len(bits) == TAG_BITS + len(n_slots):
            saved = bits[TAG_BITS:]
            if len(saved) != len(n_slots):
                return None
            for (nc, nbid, nk), lsb in zip(n_slots, saved):
                npairs = _pairs(_get_block(image, nc, nbid))
                npairs[nk, 0] = (int(npairs[nk, 0]) & ~1) | lsb
                _get_block(image, nc, nbid)[:] = npairs.reshape(BLOCK_SIZE, BLOCK_SIZE)
            return _bits_tag(bits[:TAG_BITS]), len(bits) + len(n_slots), n_slots
    return None


def embed_group_tag(image: np.ndarray, ordered_slots: Sequence[tuple[int, int, int]], tag: bytes) -> tuple[bool, int, int]:
    """Embed one 256-bit tag into an image in the supplied deterministic slot order."""
    if len(tag) != 32:
        raise ValueError("tag must be 256 bits (32 bytes)")
    return _embed_pairs(image, ordered_slots, tag)


def extract_group_tag(image: np.ndarray, ordered_slots: Sequence[tuple[int, int, int]]) -> tuple[bytes, np.ndarray, int] | None:
    """Extract a tag, returning (tag, restored copy, slots consumed), if decodable."""
    restored = np.asarray(image).copy()
    result = _extract_pairs(restored, ordered_slots)
    if result is None:
        return None
    return result[0], restored, result[1]


def _group_slots(c: int, block_ids: Sequence[int]) -> list[tuple[int, int, int]]:
    return [(c, bid, k) for k in range(PAIRS_PER_BLOCK - 1, -1, -1) for bid in block_ids]


def _whole_slots() -> list[tuple[int, int, int]]:
    return [(c, bid, k) for k in range(PAIRS_PER_BLOCK - 1, -1, -1) for c in range(CHANNELS) for bid in range(BLOCK_COUNT)]


@dataclass(frozen=True)
class ProtectResult:
    marked_image: np.ndarray
    mode: str
    image_id: bytes
    groups_per_channel: int
    embedded_tags: int
    pairs_used: int


@dataclass(frozen=True)
class VerifyResult:
    accepted: bool
    mode: str | None
    failed_groups: tuple[tuple[int, int], ...]
    group_status: tuple[tuple[int, int, bool], ...]
    recovered_image: np.ndarray | None
    reason: str


def protect_image(image: np.ndarray, user_key: bytes, image_id: bytes | None = None) -> ProtectResult:
    """Protect 512x512 RGB uint8 image; caller must privately retain ImageID."""
    source = _validate_image(image)
    key = bytes(user_key)
    if len(key) < 16:
        raise ValueError("UserKey must contain at least 128 bits")
    iid = generate_image_id() if image_id is None else _bytes(image_id, 16, "ImageID")
    step1 = _step1_image(source, key, iid)
    # Keep the Step-1 carrier for HMAC while embedding into the Step-2 copy.
    step2 = _step2_image(step1, key)
    grouped = step2.copy()
    groups_by_channel = [group_blocks(derive_keys(key, c)["Kstruct"]) for c in range(CHANNELS)]
    group_counts: list[int] = []
    pair_count = 0
    all_fit = True
    for c in range(CHANNELS):
        for ids in groups_by_channel[c]:
            mac = _group_mac(step1, key, iid, c, ids)
            ok, used, _ = _embed_pairs(grouped, _group_slots(c, ids), mac)
            if not ok:
                all_fit = False
                break
            group_counts.append(used); pair_count += used
        if not all_fit:
            break
    if all_fit:
        return ProtectResult(grouped, "group", iid, 3 * GROUPS_PER_CHANNEL, 3 * GROUPS_PER_CHANNEL, pair_count)
    whole = step2.copy()
    mac = _image_mac(step1, key, iid)
    ok, used, _ = _embed_pairs(whole, _whole_slots(), mac)
    if not ok:
        raise InsufficientCapacity("neither group mode nor whole-image mode has 256 net bits")
    return ProtectResult(whole, "whole-image", iid, 0, 1, used)


def _verify_group_attempt(marked: np.ndarray, key: bytes, iid: bytes) -> tuple[bool, tuple[tuple[int, int], ...], tuple[tuple[int, int, bool], ...]]:
    restored_step2 = marked.copy()
    failed: list[tuple[int, int]] = []
    statuses: list[tuple[int, int, bool]] = []
    group_sets = [group_blocks(derive_keys(key, c)["Kstruct"]) for c in range(CHANNELS)]
    for c in range(CHANNELS):
        for gi, ids in enumerate(group_sets[c]):
            candidate = restored_step2.copy()
            extracted = _extract_pairs(candidate, _group_slots(c, ids))
            ok = False
            if extracted is not None:
                tag = extracted[0]
                step1_candidate = candidate.copy()
                # Only this group was restored; undo Step 2 only for these four blocks.
                keys = derive_keys(key, c)
                for bid in ids:
                    pairs = _pairs(_get_block(candidate, c, bid)); out = np.empty_like(pairs)
                    r1 = block_r1(keys["Kr1"], bid)
                    for k, (x, y) in enumerate(pairs):
                        out[k] = inverse_step2_pair(int(x), int(y), r1)
                    _get_block(step1_candidate, c, bid)[:] = out.reshape(BLOCK_SIZE, BLOCK_SIZE)
                expected = _group_mac(step1_candidate, key, iid, c, ids)
                ok = hmac.compare_digest(tag, expected)
                if ok:
                    for bid in ids:
                        _get_block(restored_step2, c, bid)[:] = _get_block(candidate, c, bid)
            statuses.append((c, gi, ok))
            if not ok:
                failed.append((c, gi))
    return not failed, tuple(failed), tuple(statuses)


def _restore_group_carriers(marked: np.ndarray, key: bytes) -> np.ndarray:
    restored = marked.copy()
    for c in range(CHANNELS):
        for ids in group_blocks(derive_keys(key, c)["Kstruct"]):
            extracted = _extract_pairs(restored, _group_slots(c, ids))
            if extracted is None:
                raise AuthenticationError("group extraction failed after successful verification")
    return restored


def _try_whole_image(marked: np.ndarray, user_key: bytes, image_id: bytes) -> bool:
    candidate = marked.copy()
    extracted = _extract_pairs(candidate, _whole_slots())
    if extracted is None:
        return False
    tag = extracted[0]
    keys_by_channel = [derive_keys(user_key, c) for c in range(CHANNELS)]
    step1 = np.empty_like(candidate)
    for c in range(CHANNELS):
        keys = keys_by_channel[c]
        for bid in range(BLOCK_COUNT):
            pairs = _pairs(_get_block(candidate, c, bid)); out = np.empty_like(pairs)
            r1 = block_r1(keys["Kr1"], bid)
            for k, (x, y) in enumerate(pairs):
                out[k] = inverse_step2_pair(int(x), int(y), r1)
            _get_block(step1, c, bid)[:] = out.reshape(BLOCK_SIZE, BLOCK_SIZE)
    return hmac.compare_digest(tag, _image_mac(step1, user_key, image_id))


def verify_and_decrypt(marked_image: np.ndarray, user_key: bytes, image_id: bytes) -> VerifyResult:
    """Authenticate before recovery; failed verification never returns plaintext."""
    marked = _validate_image(marked_image)
    key = bytes(user_key); iid = _bytes(image_id, 16, "ImageID")
    groups_ok, failed, statuses = _verify_group_attempt(marked, key, iid)
    if groups_ok:
        restored_step2 = _restore_group_carriers(marked, key)
        recovered = _transform_image(restored_step2, key, iid, inverse=True)
        return VerifyResult(True, "group", (), statuses, recovered, "all 192 groups verified")
    if _try_whole_image(marked, key, iid):
        candidate = marked.copy()
        _extract_pairs(candidate, _whole_slots())
        recovered = _transform_image(candidate, key, iid, inverse=True)
        return VerifyResult(True, "whole-image", (), statuses, recovered, "whole-image code verified")
    # Failed group parses alone do not establish group mode. Report locations
    # only when at least one group authenticates (the PDF's mode-recognition rule).
    reported_failed = failed if any(ok for _, _, ok in statuses) else ()
    return VerifyResult(False, None, reported_failed, statuses, None, "authentication failed; no plaintext released")


__all__ = [
    "AuthenticationError", "InsufficientCapacity", "ProtectResult", "VerifyResult",
    "HMACDRBG", "generate_image_id", "derive_keys", "derive_group_key", "derive_image_key",
    "pair_shift", "block_r1", "group_blocks", "step1_pair", "inverse_step1_pair",
    "step2_pair", "inverse_step2_pair", "rcm_forward", "rcm_inverse", "classify_pair",
    "embed_group_tag", "extract_group_tag",
    "protect_image", "verify_and_decrypt",
]
