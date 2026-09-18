from pathlib import Path
import sys
from dataclasses import replace

import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from pipeline import (
    DemoPipelineParameters,
    block_sums,
    decrypt_rgb_image,
    encrypt_rgb_image,
    _derive_identifier_from_image,
)
from rdh import bits_from_bytes

FLIPPED_KEY = bytes([DemoPipelineParameters.key[0] ^ 0x01]) + DemoPipelineParameters.key[1:]


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
    decrypted = decrypt_rgb_image(
        encrypted.encrypted_image,
        replace(params, image_identifier=encrypted.image_identifier),
    )

    assert encrypted.encrypted_image.shape == image.shape
    assert decrypted.recovered_image.shape == image.shape


def test_pipeline_recovers_exact_original_image_and_payload():
    image = _small_rgb_image()
    params = DemoPipelineParameters()
    payload = bits_from_bytes(b"exact")

    encrypted = encrypt_rgb_image(image, payload, params)
    decrypted = decrypt_rgb_image(
        encrypted.encrypted_image,
        replace(params, image_identifier=encrypted.image_identifier),
    )

    np.testing.assert_array_equal(decrypted.recovered_image, image)
    assert decrypted.payload_bits == payload


def test_decryption_accepts_encryption_result_and_uses_stored_identifier():
    image = _small_rgb_image()
    params = DemoPipelineParameters()
    payload = bits_from_bytes(b"result-object")

    encrypted = encrypt_rgb_image(image, payload, params)
    decrypted = decrypt_rgb_image(encrypted, params)

    np.testing.assert_array_equal(decrypted.recovered_image, image)
    assert decrypted.payload_bits == payload


def test_pipeline_distributes_payload_across_rgb_channels():
    image = _small_rgb_image()
    params = DemoPipelineParameters()
    payload = bits_from_bytes(b"payload-distributed-across-rgb")

    encrypted = encrypt_rgb_image(image, payload, params)
    decrypted = decrypt_rgb_image(
        encrypted.encrypted_image,
        replace(params, image_identifier=encrypted.image_identifier),
    )

    channel_lengths = [info.payload_length for info in encrypted.rdh_infos]
    assert sum(channel_lengths) == len(payload)
    assert min(channel_lengths) > 0
    assert max(channel_lengths) - min(channel_lengths) <= 1
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
    decrypted = decrypt_rgb_image(
        encrypted.encrypted_image,
        replace(params, image_identifier=encrypted.image_identifier),
    )

    assert encrypted.encrypted_image.shape == image.shape
    assert encrypted.encrypted_image.dtype == image.dtype
    assert decrypted.recovered_image.shape == image.shape
    assert decrypted.recovered_image.dtype == image.dtype


def test_decryption_with_wrong_parameter_does_not_recover_original():
    image = _small_rgb_image()
    payload = bits_from_bytes(b"wrong")
    encrypt_params = DemoPipelineParameters()
    wrong_params = DemoPipelineParameters(key=FLIPPED_KEY)

    encrypted = encrypt_rgb_image(image, payload, encrypt_params)

    try:
        decrypted = decrypt_rgb_image(
            encrypted.encrypted_image,
            replace(wrong_params, image_identifier=encrypted.image_identifier),
        )
    except ValueError:
        return

    assert not np.array_equal(decrypted.recovered_image, image)


def test_decryption_requires_stored_image_identifier():
    image = _small_rgb_image()
    params = DemoPipelineParameters()
    encrypted = encrypt_rgb_image(image, [], params)

    try:
        decrypt_rgb_image(encrypted.encrypted_image, params)
    except ValueError as error:
        assert "image_identifier is required" in str(error)
        return

    raise AssertionError("decryption should require the stored image identifier")


def test_same_key_and_same_identifier_are_deterministic():
    image = _small_rgb_image()
    payload = bits_from_bytes(b"stable")
    params = DemoPipelineParameters(image_identifier=b"same-identifier")

    first = encrypt_rgb_image(image, payload, params)
    second = encrypt_rgb_image(image, payload, params)

    np.testing.assert_array_equal(first.upsilon_p, second.upsilon_p)
    np.testing.assert_array_equal(first.upsilon_s, second.upsilon_s)
    np.testing.assert_array_equal(first.encrypted_image, second.encrypted_image)


def test_automatic_identifier_uses_canonical_contiguous_pixel_bytes():
    image = _small_rgb_image()
    non_contiguous = np.asfortranarray(image)

    assert image.flags.c_contiguous
    assert not non_contiguous.flags.c_contiguous
    assert _derive_identifier_from_image(image) == _derive_identifier_from_image(
        non_contiguous
    )


def test_same_key_and_default_identifier_derive_different_matrices_for_different_images():
    first_image = _small_rgb_image()
    second_image = _small_rgb_image()
    second_image[8, 8] = [33, 44, 55]
    payload = bits_from_bytes(b"image-derived")
    params = DemoPipelineParameters()

    first = encrypt_rgb_image(first_image, payload, params)
    second = encrypt_rgb_image(second_image, payload, params)

    assert first.image_identifier != second.image_identifier
    assert not np.array_equal(first.upsilon_p, second.upsilon_p)
    assert not np.array_equal(first.upsilon_s, second.upsilon_s)
    assert not np.array_equal(first.encrypted_image, second.encrypted_image)

    first_decrypted = decrypt_rgb_image(
        first.encrypted_image,
        replace(params, image_identifier=first.image_identifier),
    )
    second_decrypted = decrypt_rgb_image(
        second.encrypted_image,
        replace(params, image_identifier=second.image_identifier),
    )

    np.testing.assert_array_equal(first_decrypted.recovered_image, first_image)
    np.testing.assert_array_equal(second_decrypted.recovered_image, second_image)
    assert first_decrypted.payload_bits == payload
    assert second_decrypted.payload_bits == payload


def test_same_key_and_different_identifier_change_matrices_and_ciphertext():
    image = _small_rgb_image()
    payload = bits_from_bytes(b"identifier")
    first_params = DemoPipelineParameters(image_identifier=b"image-a")
    second_params = DemoPipelineParameters(image_identifier=b"image-b")

    first = encrypt_rgb_image(image, payload, first_params)
    second = encrypt_rgb_image(image, payload, second_params)

    assert not np.array_equal(first.upsilon_p, second.upsilon_p)
    assert not np.array_equal(first.upsilon_s, second.upsilon_s)
    assert not np.array_equal(first.encrypted_image, second.encrypted_image)


def test_one_bit_key_flip_substantially_changes_ciphertext():
    image = _small_rgb_image()
    payload = bits_from_bytes(b"key-flip")
    first_params = DemoPipelineParameters(image_identifier=b"key-test-image")
    second_params = DemoPipelineParameters(
        key=FLIPPED_KEY, image_identifier=b"key-test-image"
    )

    first = encrypt_rgb_image(image, payload, first_params)
    second = encrypt_rgb_image(image, payload, second_params)

    changed_ratio = np.mean(first.encrypted_image != second.encrypted_image)
    assert changed_ratio > 0.25
