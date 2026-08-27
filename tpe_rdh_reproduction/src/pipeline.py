"""End-to-end integration of Sections 5.2-5.5.

This module wires together the already tested components:

1. Section 5.1 chaotic matrices from `chaos.py`
2. Section 5.2 permutation from `permutation.py`
3. Section 5.3 RDH from `rdh.py`
4. Section 5.4 substitution from `substitution.py`
5. Section 5.5 reverse order for decryption/recovery

PAPER AMBIGUITY / IMPLEMENTATION DECISION:
The paper does not specify an RGB payload distribution or per-channel metadata
format for RDH. This first integration embeds the user payload in channel 0
only, while channels 1 and 2 receive empty RDH payloads so their P/Z and LSB
overhead are still recoverable by the same Section 5.3 mechanism.

PAPER AMBIGUITY / IMPLEMENTATION DECISION:
This pipeline uses the existing demo assumptions from the component modules:
explicit `discard_count`, explicit `vartheta`, row-major permutation mapping,
row-major substitution pairs, and the explicit RDH metadata header.

PAPER AMBIGUITY / IMPLEMENTATION DECISION:
The paper text says only `vartheta >> 1`. The default below uses
`vartheta = 10000.0` as an inference from Fig. 4 examples such as
`0.7492 -> 7492`, not as an explicit textual parameter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

import numpy as np

from chaos import generate_upsilon_matrices
from permutation import inverse_permute_image_blocks, permute_image_blocks
from rdh import RDHEmbeddingInfo, embed_bits, extract_bits_and_recover
from substitution import inverse_substitute_channel_blocks, substitute_channel_blocks


@dataclass(frozen=True)
class DemoPipelineParameters:
    """Explicit parameters for the first reproducible integration.

    The chaotic initial values and control parameters are stated by the paper.
    `discard_count` is not numerically specified by the paper. `vartheta`
    defaults to `10000.0` as a Fig. 4 inference, not an explicit textual value.
    """

    block_size: int = 4
    x0: float = 0.3
    y0: float = 0.2
    r1: float = 50.0
    r2: float = 50.0
    discard_count: int = 0
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
        payload_bits: User payload bits. In this first integration they are
            embedded in channel 0 only.
        params: Explicit demo/reproduction parameters.

    Returns:
        `EncryptionResult` containing the final encrypted image and useful
        intermediates for tests.
    """

    _validate_rgb_image(image)
    payload = _validate_bits(payload_bits)
    height, width = image.shape[:2]

    upsilon_p, upsilon_s = generate_upsilon_matrices(
        height=height,
        width=width,
        x0=params.x0,
        y0=params.y0,
        r1=params.r1,
        r2=params.r2,
        discard_count=params.discard_count,
    )

    # Section 5.2: split RGB into channels conceptually and apply the same
    # `Upsilon_P` block template to each channel.
    permuted = permute_image_blocks(image, upsilon_p, params.block_size)

    # Section 5.3: RDH is currently implemented and tested for one channel.
    # The first integration embeds the actual payload in channel 0 only.
    marked_channels = []
    rdh_infos = []
    for channel_index in range(3):
        channel_payload = payload if channel_index == 0 else []
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
    )


def decrypt_rgb_image(
    encrypted_image: np.ndarray,
    params: DemoPipelineParameters,
) -> DecryptionResult:
    """Reverse the integrated pipeline using Section 5.5 order.

    Args:
        encrypted_image: Output image from `encrypt_rgb_image`.
        params: Same explicit parameters used during encryption.

    Returns:
        `DecryptionResult` with the exact recovered RGB image and extracted
        channel-0 payload bits.
    """

    _validate_rgb_image(encrypted_image)
    height, width = encrypted_image.shape[:2]
    upsilon_p, upsilon_s = generate_upsilon_matrices(
        height=height,
        width=width,
        x0=params.x0,
        y0=params.y0,
        r1=params.r1,
        r2=params.r2,
        discard_count=params.discard_count,
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
        payload_bits=extracted_payloads[0],
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
