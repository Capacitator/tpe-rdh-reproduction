from pathlib import Path
import sys

import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from pipeline import (
    DemoPipelineParameters,
    block_sums,
    decrypt_rgb_image,
    encrypt_rgb_image,
)
from rdh import bits_from_bytes


def _small_rgb_image() -> np.ndarray:
    image = np.zeros((32, 32, 3), dtype=np.uint8)
    image[:, :, 0] = 90
    image[:, :, 1] = 120
    image[:, :, 2] = 150

    # The first 16 top-row pixels are reserved by the RDH module for P/Z LSB
    # storage. Varying them here verifies that their original LSBs recover.
    for channel in range(3):
        image[0, :16, channel] = np.arange(16, dtype=np.uint8) + channel

    # Boundary values make sure integration keeps uint8 extremes recoverable.
    image[4, 4] = [0, 255, 0]
    image[4, 5] = [255, 0, 255]
    return image


def test_pipeline_encryption_and_decryption_run_successfully():
    image = _small_rgb_image()
    params = DemoPipelineParameters()
    payload = bits_from_bytes(b"pipeline")

    encrypted = encrypt_rgb_image(image, payload, params)
    decrypted = decrypt_rgb_image(encrypted.encrypted_image, params)

    assert encrypted.encrypted_image.shape == image.shape
    assert decrypted.recovered_image.shape == image.shape


def test_pipeline_recovers_exact_original_image_and_payload():
    image = _small_rgb_image()
    params = DemoPipelineParameters()
    payload = bits_from_bytes(b"exact")

    encrypted = encrypt_rgb_image(image, payload, params)
    decrypted = decrypt_rgb_image(encrypted.encrypted_image, params)

    np.testing.assert_array_equal(decrypted.recovered_image, image)
    assert decrypted.payload_bits == payload


def test_pipeline_preserves_thumbnail_block_sums_at_sum_preserving_stages():
    image = _small_rgb_image()
    params = DemoPipelineParameters()
    payload = bits_from_bytes(b"sum")

    encrypted = encrypt_rgb_image(image, payload, params)

    # Section 5.2 permutation only moves pixels inside each block.
    np.testing.assert_array_equal(
        block_sums(image, params.block_size),
        block_sums(encrypted.permuted_image, params.block_size),
    )

    # Section 5.4 substitution preserves the RDH-marked pair/block sums.
    # RDH itself can change pixel values, so this check is intentionally made
    # between the marked image and final encrypted image.
    np.testing.assert_array_equal(
        block_sums(encrypted.marked_image, params.block_size),
        block_sums(encrypted.encrypted_image, params.block_size),
    )


def test_pipeline_preserves_rgb_dimensions_and_dtype():
    image = _small_rgb_image()
    params = DemoPipelineParameters()

    encrypted = encrypt_rgb_image(image, [], params)
    decrypted = decrypt_rgb_image(encrypted.encrypted_image, params)

    assert encrypted.encrypted_image.shape == image.shape
    assert encrypted.encrypted_image.dtype == image.dtype
    assert decrypted.recovered_image.shape == image.shape
    assert decrypted.recovered_image.dtype == image.dtype

