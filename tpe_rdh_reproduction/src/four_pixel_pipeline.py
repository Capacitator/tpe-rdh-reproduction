"""Four-pixel sum-preserving TPE adapter with native RDH authentication tags.

The supplied Four-Pixel SPE paper does not define an auxiliary-payload
container. This adapter embeds keyed per-channel 256-bit image tags (and the
caller's payload in the red-channel stream) using the repository's reversible
histogram-shifting RDH stage after block permutation and before four-pixel
substitution. Decryption reverses substitution, extracts and verifies each
tag, exactly recovers the permuted carrier, then reverses block permutation.

The paper's keyed schedule is not treated as interchangeable with the
repository's existing 2D-CSM schedule. This reproducible prototype maps the
repository's 2D-CSM values to r in [1,255], matching the paper's stated key
domain while retaining a different schedule. This is an explicit adaptation,
not a bit-for-bit reproduction of the paper's key schedule.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import numpy as np

from chaos import generate_upsilon_matrices
from permutation import inverse_permute_image_blocks, permute_image_blocks
from pipeline import (
    IdentifierLike,
    _resolve_encryption_identifier,
    _require_decryption_identifier,
    _validate_bits,
    _validate_rgb_image,
)
from rdh import bits_from_bytes, bytes_from_bits, embed_bits, extract_bits_and_recover
from four_pixel_spe import transform_block

BLOCK_SIZE = 32
SIDECAR_PAYLOAD = False
RDH_TAG_BYTES = 32


@dataclass(frozen=True)
class DemoPipelineParameters:
    block_size: int = BLOCK_SIZE
    # No public fixed demo key: callers must supply a private 256-bit key.
    key: Optional[bytes] = None
    image_identifier: Optional[IdentifierLike] = None
    vartheta: float = 10000.0


@dataclass(frozen=True)
class EncryptionResult:
    encrypted_image: np.ndarray
    upsilon_p: Tuple[np.ndarray, np.ndarray, np.ndarray]
    upsilon_s: Tuple[np.ndarray, np.ndarray, np.ndarray]
    permuted_image: np.ndarray
    marked_image: np.ndarray
    rdh_infos: tuple = ()
    image_identifier: IdentifierLike = b""
    payload_bits: Tuple[int, ...] = ()


@dataclass(frozen=True)
class DecryptionResult:
    recovered_image: np.ndarray
    payload_bits: List[int]
    recovered_permuted_image: np.ndarray
    recovered_marked_image: np.ndarray


def _channel_key(master_key: bytes, channel: int) -> bytes:
    if len(master_key) != 32:
        raise ValueError("four-pixel TPE key must be exactly 32 bytes")
    import hashlib, hmac
    return hmac.new(master_key, b"four-pixel-tpe:channel:v1\x00" + bytes([channel]), hashlib.sha256).digest()


def _keys_from_matrix(matrix: np.ndarray, block_y: int, block_x: int) -> np.ndarray:
    y0, x0 = block_y * BLOCK_SIZE, block_x * BLOCK_SIZE
    u = np.asarray(matrix[y0:y0 + BLOCK_SIZE, x0:x0 + BLOCK_SIZE], dtype=np.float64).reshape(-1)[::4]
    # The article maps unit-interval outputs by floor(255*u)+1, yielding
    # r in {1,...,255}. First map this repository's [-1,1] domain to [0,1].
    unit=(np.clip(u,-1.0,1.0)+1.0)/2.0
    q=np.floor(255.0*unit).astype(np.int64)+1
    return np.clip(q,1,255).astype(np.uint8)


def _apply_spe(image: np.ndarray, matrices: Sequence[np.ndarray], inverse: bool = False) -> np.ndarray:
    h, w, channels = image.shape
    out = np.empty_like(image)
    for c in range(channels):
        rows, cols = h // BLOCK_SIZE, w // BLOCK_SIZE
        for by in range(rows):
            for bx in range(cols):
                y0, x0 = by * BLOCK_SIZE, bx * BLOCK_SIZE
                block = image[y0:y0 + BLOCK_SIZE, x0:x0 + BLOCK_SIZE, c]
                keys = _keys_from_matrix(matrices[c], by, bx)
                out[y0:y0 + BLOCK_SIZE, x0:x0 + BLOCK_SIZE, c] = transform_block(block, keys, inverse=inverse)
    return out


def _generate_channel_matrices(height: int, width: int, params: DemoPipelineParameters,
                               image_identifier: IdentifierLike):
    if params.block_size != BLOCK_SIZE:
        raise ValueError("four-pixel authenticated prototype requires 32x32 blocks")
    if params.key is None:
        raise ValueError("four-pixel TPE key is required; no default demonstration key is provided")
    key = bytes(params.key)
    if len(key) != 32:
        raise ValueError("four-pixel TPE key must be exactly 32 bytes")
    p_mats, s_mats = [], []
    for channel in range(3):
        p, s = generate_upsilon_matrices(height, width, _channel_key(key, channel), image_identifier)
        p_mats.append(p)
        s_mats.append(s)
    return tuple(p_mats), tuple(s_mats)


def _rdh_tag(key: bytes, image_identifier: IdentifierLike, channel: int,
             carrier: np.ndarray, payload_bits: Sequence[int]) -> bytes:
    """Bind the recovered pre-RDH channel and payload to this TPE image."""
    import hashlib, hmac
    image_id = (image_identifier.encode("utf-8") if isinstance(image_identifier, str)
                else bytes(image_identifier))
    payload = bytes(int(bit) for bit in payload_bits)
    message = (b"four-pixel-rdh-auth:v1\x00" + len(image_id).to_bytes(2, "big") + image_id
               + bytes([channel]) + len(payload).to_bytes(8, "big") + payload
               + np.ascontiguousarray(carrier).tobytes())
    return hmac.new(_channel_key(key, channel), message, hashlib.sha256).digest()


def encrypt_rgb_image(image: np.ndarray, payload_bits: Sequence[int],
                      params: DemoPipelineParameters) -> EncryptionResult:
    _validate_rgb_image(image)
    if image.shape[0] % BLOCK_SIZE or image.shape[1] % BLOCK_SIZE:
        raise ValueError("image dimensions must be multiples of 32")
    payload = _validate_bits(payload_bits)
    image_identifier = _resolve_encryption_identifier(image, params.image_identifier)
    h, w, _ = image.shape
    p_mats, s_mats = _generate_channel_matrices(h, w, params, image_identifier)
    permuted = np.stack([
        permute_image_blocks(image[:, :, c], p_mats[c], BLOCK_SIZE) for c in range(3)
    ], axis=2)
    marked = np.empty_like(permuted)
    rdh_infos = []
    for channel in range(3):
        channel_payload = payload if channel == 0 else []
        tag = _rdh_tag(params.key, image_identifier, channel, permuted[:, :, channel], channel_payload)
        carrier_bits = bits_from_bytes(tag) + [int(bit) for bit in channel_payload]
        marked[:, :, channel], info = embed_bits(permuted[:, :, channel], carrier_bits)
        rdh_infos.append(info)
    encrypted = _apply_spe(marked, s_mats)
    return EncryptionResult(encrypted, p_mats, s_mats, permuted, marked,
                            tuple(rdh_infos), image_identifier, tuple(payload))


def decrypt_rgb_image(encrypted: EncryptionResult | np.ndarray,
                      params: DemoPipelineParameters,
                      payload_bits: Sequence[int] | None = None) -> DecryptionResult:
    if isinstance(encrypted, EncryptionResult):
        ciphertext = encrypted.encrypted_image
        image_identifier = encrypted.image_identifier
    else:
        ciphertext = np.asarray(encrypted)
        image_identifier = _require_decryption_identifier(params.image_identifier)
    _validate_rgb_image(ciphertext)
    if ciphertext.shape[0] % BLOCK_SIZE or ciphertext.shape[1] % BLOCK_SIZE:
        raise ValueError("image dimensions must be multiples of 32")
    h, w, _ = ciphertext.shape
    p_mats, s_mats = _generate_channel_matrices(h, w, params, image_identifier)
    recovered_marked = _apply_spe(ciphertext, s_mats, inverse=True)
    recovered_permuted = np.empty_like(recovered_marked)
    recovered_payload: list[int] | None = None
    import hmac
    for channel in range(3):
        extracted, recovered_channel = extract_bits_and_recover(recovered_marked[:, :, channel])
        if len(extracted) < RDH_TAG_BYTES * 8:
            raise ValueError("RDH authentication payload is truncated")
        tag = bytes_from_bits(extracted[:RDH_TAG_BYTES * 8])
        channel_payload = extracted[RDH_TAG_BYTES * 8:] if channel == 0 else []
        expected = _rdh_tag(params.key, image_identifier, channel, recovered_channel, channel_payload)
        if not hmac.compare_digest(tag, expected):
            raise ValueError(f"RDH authentication tag failed for channel {channel}")
        if channel == 0:
            recovered_payload = channel_payload
        recovered_permuted[:, :, channel] = recovered_channel
    if payload_bits is not None and recovered_payload != _validate_bits(payload_bits):
        raise ValueError("RDH payload does not match the expected payload")
    recovered = np.stack([
        inverse_permute_image_blocks(recovered_permuted[:, :, c], p_mats[c], BLOCK_SIZE)
        for c in range(3)
    ], axis=2)
    return DecryptionResult(recovered, recovered_payload or [], recovered_permuted, recovered_marked)
