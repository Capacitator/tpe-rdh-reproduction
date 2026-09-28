from pathlib import Path
import sys

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "experiments"))

from pipeline import DemoPipelineParameters, encrypt_rgb_image
from run_nist_sp800_22 import packed_bits, parse_status, quantize_chaos


def test_binary_stream_construction_is_deterministic_and_exact_length():
    values = np.array([0, 1, 127, 128, 255], dtype=np.uint8)
    assert packed_bits(values, 32) == packed_bits(values.copy(), 32)
    assert len(packed_bits(values, 32)) == 32
    assert packed_bits(np.array([0x81], dtype=np.uint8), 8) == "10000001"


def test_actual_pipeline_streams_are_reproducible():
    image = np.zeros((32, 32, 3), dtype=np.uint8)
    image[:] = (70, 110, 150)
    for channel in range(3):
        image[0, :16, channel] = np.arange(16, dtype=np.uint8) + channel
    params = DemoPipelineParameters()
    first = encrypt_rgb_image(image, [], params)
    second = encrypt_rgb_image(image, [], params)
    for field in ("upsilon_p", "upsilon_s", "encrypted_image"):
        left = getattr(first, field)
        right = getattr(second, field)
        if field.startswith("upsilon"):
            left, right = quantize_chaos(left), quantize_chaos(right)
        assert packed_bits(left, 128) == packed_bits(right, 128)


def test_chaotic_quantization_is_deterministic_and_clipped():
    values = np.array([-2.0, -1.0, 0.0, 1.0, 2.0])
    expected = np.array([0, 0, 128, 255, 255], dtype=np.uint8)
    np.testing.assert_array_equal(quantize_chaos(values), expected)
    np.testing.assert_array_equal(quantize_chaos(values), quantize_chaos(values))


def test_same_key_different_images_produce_different_identifier_and_streams():
    first_image = np.zeros((32, 32, 3), dtype=np.uint8)
    first_image[:] = (70, 110, 150)
    second_image = first_image.copy()
    second_image[10, 10] = (71, 111, 151)
    params = DemoPipelineParameters()
    first = encrypt_rgb_image(first_image, [], params)
    second = encrypt_rgb_image(second_image, [], params)

    assert first.image_identifier != second.image_identifier
    assert packed_bits(quantize_chaos(first.upsilon_p), 64) != packed_bits(
        quantize_chaos(second.upsilon_p), 64
    )
    assert packed_bits(quantize_chaos(first.upsilon_s), 64) != packed_bits(
        quantize_chaos(second.upsilon_s), 64
    )
    assert packed_bits(first.encrypted_image, 64) != packed_bits(second.encrypted_image, 64)


def test_result_status_parser_handles_pass_fail_and_not_applicable():
    assert parse_status("0.05") == "pass"
    assert parse_status("0.009") == "fail"
    assert parse_status("----") == "not-applicable"
    assert parse_status(None) == "not-applicable"
