"""Four-pixel sum-preserving TPE adapter for authenticated integration.

The supplied Four-Pixel SPE paper does not define an auxiliary-payload
container. The authenticated adapter therefore keeps the TPE image transform
pure and carries caller payload bits in the existing ChaCha20-Poly1305-protected
authentication sidecar. This avoids altering the paper transform's block sums.

The paper's chaotic schedule is not treated as interchangeable with the
repository's existing 2D-CSM schedule. This reproducible prototype uses the
established 2D-CSM permutation schedule and quantizes its substitution matrix
to r in [1,255]. This is an explicit adaptation, not bit-for-bit reproduction
of the paper's chaotic-key schedule.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import numpy as np

from chaos import generate_upsilon_matrices
from permutation import inverse_permute_image_blocks, permute_image_blocks
from pipeline import (
    DemoPipelineParameters as _LegacyParams,
    IdentifierLike,
    _resolve_encryption_identifier,
    _require_decryption_identifier,
    _validate_bits,
    _validate_rgb_image,
)
from four_pixel_spe import transform_block

BLOCK_SIZE = 32
SIDECAR_PAYLOAD = True


@dataclass(frozen=True)
class DemoPipelineParameters:
    block_size: int = BLOCK_SIZE
    key: bytes = _LegacyParams().key
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
    # Existing 2D-CSM produces values in [-1,1]. Normalize and quantize to
    # the paper's nonzero byte-key set {1,...,255} using an explicit rule.
    q = np.floor(127.0 * (np.clip(u, -1.0, 1.0) + 1.0)).astype(np.int64)
    return (np.clip(q, 0, 254) + 1).astype(np.uint8)


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
    key = bytes(params.key)
    if len(key) != 32:
        raise ValueError("four-pixel TPE key must be exactly 32 bytes")
    p_mats, s_mats = [], []
    for channel in range(3):
        p, s = generate_upsilon_matrices(height, width, _channel_key(key, channel), image_identifier)
        p_mats.append(p)
        s_mats.append(s)
    return tuple(p_mats), tuple(s_mats)


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
    encrypted = _apply_spe(permuted, s_mats)
    return EncryptionResult(encrypted, p_mats, s_mats, permuted, permuted,
                            (), image_identifier, tuple(payload))


def decrypt_rgb_image(encrypted: EncryptionResult | np.ndarray,
                      params: DemoPipelineParameters,
                      payload_bits: Sequence[int] | None = None) -> DecryptionResult:
    if isinstance(encrypted, EncryptionResult):
        ciphertext = encrypted.encrypted_image
        image_identifier = encrypted.image_identifier
        stored_payload = list(encrypted.payload_bits)
    else:
        ciphertext = np.asarray(encrypted)
        image_identifier = _require_decryption_identifier(params.image_identifier)
        stored_payload = [] if payload_bits is None else _validate_bits(payload_bits)
    _validate_rgb_image(ciphertext)
    if ciphertext.shape[0] % BLOCK_SIZE or ciphertext.shape[1] % BLOCK_SIZE:
        raise ValueError("image dimensions must be multiples of 32")
    h, w, _ = ciphertext.shape
    p_mats, s_mats = _generate_channel_matrices(h, w, params, image_identifier)
    recovered_permuted = _apply_spe(ciphertext, s_mats, inverse=True)
    recovered = np.stack([
        inverse_permute_image_blocks(recovered_permuted[:, :, c], p_mats[c], BLOCK_SIZE)
        for c in range(3)
    ], axis=2)
    return DecryptionResult(recovered, stored_payload, recovered_permuted, recovered_permuted)
