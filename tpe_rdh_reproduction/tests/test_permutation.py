from pathlib import Path
import sys

import numpy as np
import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from chaos import generate_upsilon_matrices
from permutation import (
    inverse_permute_image_blocks,
    permutation_indices_from_upsilon_block,
    permute_image_blocks,
)

TEST_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
    "102132435465768798a9babbdcedfe0f"
)
TEST_IDENTIFIER = b"permutation-test-image"


def _synthetic_rgb_image(height: int, width: int) -> np.ndarray:
    values = np.arange(height * width * 3, dtype=np.uint16)
    return values.reshape(height, width, 3)


def _assert_block_sums_preserved(
    original: np.ndarray, permuted: np.ndarray, block_size: int
) -> None:
    height, width = original.shape[:2]
    for row in range(0, height, block_size):
        for col in range(0, width, block_size):
            original_block = original[row : row + block_size, col : col + block_size]
            permuted_block = permuted[row : row + block_size, col : col + block_size]
            np.testing.assert_array_equal(
                original_block.sum(axis=(0, 1)), permuted_block.sum(axis=(0, 1))
            )


def test_permutation_indices_use_stable_ascending_sort_decision():
    upsilon_block = np.array([[0.3, -0.2], [0.3, 0.1]])

    indices = permutation_indices_from_upsilon_block(upsilon_block)

    np.testing.assert_array_equal(indices, np.array([1, 3, 0, 2]))


def test_permutation_then_inverse_recovers_exact_original_rgb_image():
    image = _synthetic_rgb_image(8, 8)
    upsilon_p, _ = generate_upsilon_matrices(8, 8, TEST_KEY, TEST_IDENTIFIER)

    permuted = permute_image_blocks(image, upsilon_p, block_size=4)
    recovered = inverse_permute_image_blocks(permuted, upsilon_p, block_size=4)

    np.testing.assert_array_equal(recovered, image)


def test_permutation_then_inverse_recovers_exact_original_2d_channel():
    image = np.arange(64, dtype=np.uint8).reshape(8, 8)
    upsilon_p, _ = generate_upsilon_matrices(8, 8, TEST_KEY, TEST_IDENTIFIER)

    permuted = permute_image_blocks(image, upsilon_p, block_size=4)
    recovered = inverse_permute_image_blocks(permuted, upsilon_p, block_size=4)

    np.testing.assert_array_equal(recovered, image)


def test_permutation_preserves_every_block_pixel_sum():
    image = _synthetic_rgb_image(8, 8)
    upsilon_p, _ = generate_upsilon_matrices(8, 8, TEST_KEY, TEST_IDENTIFIER)

    permuted = permute_image_blocks(image, upsilon_p, block_size=4)

    _assert_block_sums_preserved(image, permuted, block_size=4)


def test_permutation_shape_is_unchanged():
    image = _synthetic_rgb_image(8, 8)
    upsilon_p, _ = generate_upsilon_matrices(8, 8, TEST_KEY, TEST_IDENTIFIER)

    permuted = permute_image_blocks(image, upsilon_p, block_size=4)

    assert permuted.shape == image.shape
    assert permuted.dtype == image.dtype


def test_permutation_is_deterministic_with_same_upsilon_and_block_size():
    image = _synthetic_rgb_image(8, 8)
    upsilon_p, _ = generate_upsilon_matrices(8, 8, TEST_KEY, TEST_IDENTIFIER)

    first = permute_image_blocks(image, upsilon_p, block_size=4)
    second = permute_image_blocks(image, upsilon_p, block_size=4)

    np.testing.assert_array_equal(first, second)


def test_permutation_rejects_mismatched_upsilon_shape():
    image = _synthetic_rgb_image(8, 8)
    upsilon_p = np.ones((7, 8), dtype=np.float64)

    with pytest.raises(ValueError, match="match the image"):
        permute_image_blocks(image, upsilon_p, block_size=4)


def test_permutation_rejects_dimensions_not_divisible_by_block_size():
    image = _synthetic_rgb_image(7, 8)
    upsilon_p = np.ones((7, 8), dtype=np.float64)

    with pytest.raises(ValueError, match="divisible"):
        permute_image_blocks(image, upsilon_p, block_size=4)

