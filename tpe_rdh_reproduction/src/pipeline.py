"""End-to-end integration of Sections 5.2-5.5.

This module wires together the already tested components:

1. Section 5.1 chaotic matrices from `chaos.py`
2. Section 5.2 permutation from `permutation.py`
3. Section 5.3 RDH from `rdh.py`
4. Section 5.4 substitution from `substitution.py`
5. Section 5.5 reverse order for decryption/recovery

PAPER AMBIGUITY / IMPLEMENTATION DECISION:
The paper does not specify an RGB payload distribution or per-channel metadata
format for RDH. This integration splits the user payload into three contiguous
chunks and embeds one chunk per RGB channel. Decryption concatenates the three
extracted streams in channel order.

PAPER AMBIGUITY / IMPLEMENTATION DECISION:
This pipeline uses the documented key-to-chaos convention in `chaos.py`,
explicit `vartheta`, row-major permutation mapping, row-major substitution
pairs, and the explicit RDH metadata header.

PAPER AMBIGUITY / IMPLEMENTATION DECISION:
The paper text says only `vartheta >> 1`. The default below uses
`vartheta = 10000.0` as an inference from Fig. 4 examples such as
`0.7492 -> 7492`, not as an explicit textual parameter.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple, Union

import numpy as np

from chaos import generate_upsilon_matrices
from permutation import inverse_permute_image_blocks, permute_image_blocks
from rdh import RDHEmbeddingInfo, embed_bits, extract_bits_and_recover
from substitution import inverse_substitute_channel_blocks, substitute_channel_blocks

DEFAULT_DEMO_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
    "102132435465768798a9babbdcedfe0f"
)
IdentifierLike = Union[bytes, str, int]


@dataclass(frozen=True)
class DemoPipelineParameters:
    """Explicit parameters for the first reproducible integration.

    `key` is a 256-bit value used by `chaos.py` to derive `x0`, `y0`, `r1`,
    `r2`, and `kappa_1`. `image_identifier` is the Section 5.1 image
    identifier `T`; when omitted for encryption it is derived from the
    plaintext image bytes so key reuse across images still diversifies the
    chaotic matrices. The resolved identifier returned by `EncryptionResult`
    must be supplied during decryption so `kappa_2` can be reconstructed.
    `vartheta` defaults to `10000.0` as a Fig. 4 inference, not an explicit
    textual value.
    """

    block_size: int = 4
    key: bytes = DEFAULT_DEMO_KEY
    image_identifier: Optional[IdentifierLike] = None
    vartheta: float = 10000.0


@dataclass(frozen=True)
class EncryptionResult:
    """All outputs needed for testing and later decryption."""

    encrypted_image: np.ndarray
    upsilon_p: np.ndarray
    upsilon_s: np.ndarray
    permuted_image: np.ndarray
    marked_image: np.ndarray
    rdh_infos: Tuple[RDHEmbeddingInfo, RDHEmbeddingInfo, RDHEmbeddingInfo]
    image_identifier: IdentifierLike


@dataclass(frozen=True)
class DecryptionResult:
    """Recovered image and extracted payload from Section 5.5 order."""

    recovered_image: np.ndarray
    payload_bits: List[int]
    recovered_permuted_image: np.ndarray
    recovered_marked_image: np.ndarray


def encrypt_rgb_image(
    image: np.ndarray,
    payload_bits: Sequence[int],
    params: DemoPipelineParameters,
) -> EncryptionResult:
    """Encrypt one RGB image using Sections 5.2-5.4 in paper order.

    Args:
        image: 3D `uint8` RGB image with shape `(height, width, 3)`.
        payload_bits: User payload bits split across RGB channels in channel
            order.
        params: Explicit demo/reproduction parameters.

    Returns:
        `EncryptionResult` containing the final encrypted image and useful
        intermediates for tests.
    """

    _validate_rgb_image(image)
    payload = _validate_bits(payload_bits)
    height, width = image.shape[:2]
    image_identifier = _resolve_encryption_identifier(image, params.image_identifier)

    upsilon_p, upsilon_s = generate_upsilon_matrices(
        height=height,
        width=width,
        key=params.key,
        image_identifier=image_identifier,
    )

    # Section 5.2: split RGB into channels conceptually and apply the same
    # `Upsilon_P` block template to each channel.
    permuted = permute_image_blocks(image, upsilon_p, params.block_size)

    # Section 5.3: RDH is implemented per channel. Split one logical payload
    # across RGB channels so the pipeline uses all three channel capacities.
    channel_payloads = _split_payload_across_channels(payload, channel_count=3)
    marked_channels = []
    rdh_infos = []
    for channel_index, channel_payload in enumerate(channel_payloads):
        marked_channel, info = embed_bits(permuted[:, :, channel_index], channel_payload)
        marked_channels.append(marked_channel)
        rdh_infos.append(info)
    marked = np.stack(marked_channels, axis=2)

    # Section 5.4: substitution is sum-preserving per pixel pair, so it keeps
    # the RDH-marked block sums fixed while changing pixel values nonlinearly.
    encrypted_channels = [
        substitute_channel_blocks(
            marked[:, :, channel_index],
            upsilon_s,
            params.block_size,
            params.vartheta,
        )
        for channel_index in range(3)
    ]
    encrypted = np.stack(encrypted_channels, axis=2)

    return EncryptionResult(
        encrypted_image=encrypted,
        upsilon_p=upsilon_p,
        upsilon_s=upsilon_s,
        permuted_image=permuted,
        marked_image=marked,
        rdh_infos=tuple(rdh_infos),  # type: ignore[arg-type]
        image_identifier=image_identifier,
    )


def decrypt_rgb_image(
    encrypted: Union[EncryptionResult, np.ndarray],
    params: DemoPipelineParameters,
) -> DecryptionResult:
    """Reverse the integrated pipeline using Section 5.5 order.

    Args:
        encrypted: Either the complete output from `encrypt_rgb_image`, or its
            encrypted image array. When an `EncryptionResult` is supplied,
            its stored image identifier is used automatically. Array callers
            must provide the stored identifier in `params`.
        params: Same explicit parameters used during encryption.

    Returns:
        `DecryptionResult` with the exact recovered RGB image and extracted
        payload bits concatenated from channels 0, 1, and 2.
    """

    if isinstance(encrypted, EncryptionResult):
        encrypted_image = encrypted.encrypted_image
        image_identifier = encrypted.image_identifier
    else:
        encrypted_image = encrypted
        image_identifier = _require_decryption_identifier(params.image_identifier)

    _validate_rgb_image(encrypted_image)
    height, width = encrypted_image.shape[:2]
    upsilon_p, upsilon_s = generate_upsilon_matrices(
        height=height,
        width=width,
        key=params.key,
        image_identifier=image_identifier,
    )

    recovered_marked_channels = [
        inverse_substitute_channel_blocks(
            encrypted_image[:, :, channel_index],
            upsilon_s,
            params.block_size,
            params.vartheta,
        )
        for channel_index in range(3)
    ]
    recovered_marked = np.stack(recovered_marked_channels, axis=2)

    recovered_permuted_channels = []
    extracted_payloads = []
    for channel_index in range(3):
        payload_bits, recovered_channel = extract_bits_and_recover(
            recovered_marked[:, :, channel_index]
        )
        recovered_permuted_channels.append(recovered_channel)
        extracted_payloads.append(payload_bits)
    recovered_permuted = np.stack(recovered_permuted_channels, axis=2)

    recovered = inverse_permute_image_blocks(
        recovered_permuted, upsilon_p, params.block_size
    )

    return DecryptionResult(
        recovered_image=recovered,
        payload_bits=[
            bit for channel_payload in extracted_payloads for bit in channel_payload
        ],
        recovered_permuted_image=recovered_permuted,
        recovered_marked_image=recovered_marked,
    )


def block_sums(image: np.ndarray, block_size: int) -> np.ndarray:
    """Return per-block, per-channel sums for thumbnail preservation checks."""

    _validate_rgb_image(image)
    if image.shape[0] % block_size != 0 or image.shape[1] % block_size != 0:
        raise ValueError("image dimensions must be divisible by block_size")

    sums = []
    for row in range(0, image.shape[0], block_size):
        row_sums = []
        for col in range(0, image.shape[1], block_size):
            block = image[row : row + block_size, col : col + block_size]
            row_sums.append(block.sum(axis=(0, 1)))
        sums.append(row_sums)
    return np.array(sums)


def _validate_rgb_image(image: np.ndarray) -> None:
    if image.ndim != 3 or image.shape[2] != 3:
        raise ValueError("image must be a channel-last RGB array")
    if image.dtype != np.uint8:
        raise ValueError("image must have dtype uint8")


def _validate_bits(bits: Sequence[int]) -> List[int]:
    result = [int(bit) for bit in bits]
    if any(bit not in (0, 1) for bit in result):
        raise ValueError("payload_bits must contain only 0 and 1")
    return result


def _resolve_encryption_identifier(
    image: np.ndarray, image_identifier: Optional[IdentifierLike]
) -> IdentifierLike:
    if image_identifier is not None:
        return image_identifier
    return _derive_identifier_from_image(image)


def _require_decryption_identifier(
    image_identifier: Optional[IdentifierLike],
) -> IdentifierLike:
    if image_identifier is None:
        raise ValueError(
            "image_identifier is required when decrypting an image array; "
            "pass the EncryptionResult directly or provide its stored "
            "image_identifier through DemoPipelineParameters"
        )
    return image_identifier


def _derive_identifier_from_image(image: np.ndarray) -> bytes:
    """Hash a canonical in-memory RGB image representation.

    RGB channel order, the uint8 dtype name, the three dimensions, and the
    C-contiguous row-major pixel bytes are all authenticated explicitly. No
    encoded or compressed image-file representation is involved.
    """

    contiguous = np.ascontiguousarray(image)
    digest = hashlib.sha256()
    digest.update(b"tpe-rdh:image-id:v1\x00")
    digest.update(b"RGB\x00")
    digest.update(contiguous.dtype.name.encode("ascii") + b"\x00")
    digest.update(len(contiguous.shape).to_bytes(1, "big"))
    for dimension in contiguous.shape:
        digest.update(int(dimension).to_bytes(8, "big"))
    digest.update(contiguous.tobytes(order="C"))
    return digest.digest()


def _split_payload_across_channels(
    payload_bits: Sequence[int], channel_count: int
) -> List[List[int]]:
    if channel_count <= 0:
        raise ValueError("channel_count must be positive")

    payload = list(payload_bits)
    base_size, remainder = divmod(len(payload), channel_count)
    chunks: List[List[int]] = []
    start = 0
    for channel_index in range(channel_count):
        chunk_size = base_size + (1 if channel_index < remainder else 0)
        end = start + chunk_size
        chunks.append(payload[start:end])
        start = end
    return chunks
