"""Section 5.2 block permutation encryption.

The paper says `Upsilon_P` controls permutation by sorting each chaotic block
and using the reordered positions as a template for pixel rearrangement. This
module implements only that Section 5.2 step and its inverse.

PAPER AMBIGUITY: Section 5.2 does not specify sorting direction, tie handling,
flattening order, or source-to-destination mapping. The implementation decision
here is:

- flatten each `b x b` block in row-major order;
- use stable ascending sort of the matching `Upsilon_P` block;
- form the encrypted flat block as `plain_flat[sorted_indices]`;
- invert by assigning `plain_flat[sorted_indices] = encrypted_flat`.

This decision is simple, deterministic, and exactly reversible, but it should
be revisited if the paper PDF/Algorithm figure provides a different convention.
"""

from __future__ import annotations

from typing import Iterator, Tuple

import numpy as np


BlockOrigin = Tuple[int, int]


def _validate_permutation_inputs(
    image: np.ndarray, upsilon_p: np.ndarray, block_size: int
) -> None:
    """Validate the shape constraints required by Section 5.2 blocks."""

    if image.ndim not in (2, 3):
        raise ValueError("image must be a 2D channel or 3D channel-last image")
    if upsilon_p.ndim != 2:
        raise ValueError("upsilon_p must be a 2D matrix")
    if block_size <= 0:
        raise ValueError("block_size must be positive")

    height, width = image.shape[:2]
    if upsilon_p.shape != (height, width):
        raise ValueError("upsilon_p must match the image height and width")
    if height % block_size != 0 or width % block_size != 0:
        raise ValueError("image dimensions must be divisible by block_size")


def _block_origins(height: int, width: int, block_size: int) -> Iterator[BlockOrigin]:
    """Yield top-left coordinates for non-overlapping `b x b` blocks."""

    for row in range(0, height, block_size):
        for col in range(0, width, block_size):
            yield row, col


def permutation_indices_from_upsilon_block(upsilon_block: np.ndarray) -> np.ndarray:
    """Return deterministic Section 5.2 pixel-order indices for one block.

    Args:
        upsilon_block: One `b x b` block from `Upsilon_P`.

    Returns:
        A 1D integer index array. Applying this array to a row-major flattened
        image block reorders its pixels according to sorted chaotic values.

    Paper reference:
        Section 5.2. `Upsilon_P` is sorted block-by-block to create the
        permutation template used on the corresponding image block.
    """

    # Stable sorting gives deterministic behavior even if two chaotic values
    # compare equal. The paper does not state tie handling, so we make it
    # explicit instead of leaving NumPy's default quicksort instability.
    return np.argsort(upsilon_block.reshape(-1), kind="stable")


def permute_image_blocks(
    image: np.ndarray, upsilon_p: np.ndarray, block_size: int
) -> np.ndarray:
    """Permute an image or single channel using Section 5.2 `Upsilon_P` blocks.

    Args:
        image: 2D grayscale/channel matrix or 3D channel-last image.
        upsilon_p: Section 5.1 permutation-control matrix with matching height
            and width.
        block_size: Thumbnail block size `b`.

    Returns:
        A new array with the same shape and dtype as `image`.

    The operation preserves every block's pixel multiset and therefore every
    block sum. That is the property Section 5.2 needs before later
    thumbnail-preserving stages are applied.
    """

    _validate_permutation_inputs(image, upsilon_p, block_size)

    height, width = image.shape[:2]
    result = np.empty_like(image)

    for row, col in _block_origins(height, width, block_size):
        upsilon_block = upsilon_p[row : row + block_size, col : col + block_size]
        sorted_indices = permutation_indices_from_upsilon_block(upsilon_block)

        if image.ndim == 2:
            image_block = image[row : row + block_size, col : col + block_size]
            result_block = image_block.reshape(-1)[sorted_indices].reshape(
                block_size, block_size
            )
            result[row : row + block_size, col : col + block_size] = result_block
        else:
            for channel in range(image.shape[2]):
                image_block = image[
                    row : row + block_size, col : col + block_size, channel
                ]
                result_block = image_block.reshape(-1)[sorted_indices].reshape(
                    block_size, block_size
                )
                result[
                    row : row + block_size, col : col + block_size, channel
                ] = result_block

    return result


def inverse_permute_image_blocks(
    permuted_image: np.ndarray, upsilon_p: np.ndarray, block_size: int
) -> np.ndarray:
    """Reverse `permute_image_blocks` using the same Section 5.2 mappings.

    Args:
        permuted_image: Output of `permute_image_blocks`.
        upsilon_p: Same `Upsilon_P` matrix used for permutation.
        block_size: Same thumbnail block size `b` used for permutation.

    Returns:
        A new array with the exact original pixel order restored.

    Paper reference:
        Section 5.5 reverses permutation after RDH recovery and substitution
        decryption. This helper implements only that inverse permutation part.
    """

    _validate_permutation_inputs(permuted_image, upsilon_p, block_size)

    height, width = permuted_image.shape[:2]
    result = np.empty_like(permuted_image)

    for row, col in _block_origins(height, width, block_size):
        upsilon_block = upsilon_p[row : row + block_size, col : col + block_size]
        sorted_indices = permutation_indices_from_upsilon_block(upsilon_block)

        if permuted_image.ndim == 2:
            block = permuted_image[row : row + block_size, col : col + block_size]
            recovered_flat = np.empty(block_size * block_size, dtype=block.dtype)
            recovered_flat[sorted_indices] = block.reshape(-1)
            result[row : row + block_size, col : col + block_size] = (
                recovered_flat.reshape(block_size, block_size)
            )
        else:
            for channel in range(permuted_image.shape[2]):
                block = permuted_image[
                    row : row + block_size, col : col + block_size, channel
                ]
                recovered_flat = np.empty(block_size * block_size, dtype=block.dtype)
                recovered_flat[sorted_indices] = block.reshape(-1)
                result[
                    row : row + block_size, col : col + block_size, channel
                ] = recovered_flat.reshape(block_size, block_size)

    return result

