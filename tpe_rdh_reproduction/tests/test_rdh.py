from pathlib import Path
import sys

import numpy as np
import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from rdh import (
    bits_from_bytes,
    bytes_from_bits,
    embed_bits,
    extract_bits_and_recover,
    find_histogram_peak_and_zero,
)


def _base_channel(peak: int, neighbor_to_block_zero: int, shape=(24, 24)) -> np.ndarray:
    channel = np.full(shape, peak, dtype=np.uint8)
    channel[0, :16] = np.arange(16, dtype=np.uint8)
    channel[1, 0] = neighbor_to_block_zero
    channel[1, 1] = 0
    channel[1, 2] = 255
    return channel


def test_payload_is_extracted_exactly_and_image_recovers_for_p_less_than_z():
    channel = _base_channel(peak=10, neighbor_to_block_zero=9)
    payload = bits_from_bytes(b"rdh")

    marked, info = embed_bits(channel, payload)
    extracted, recovered = extract_bits_and_recover(marked)

    assert info.peak == 10
    assert info.zero == 11
    assert extracted == payload
    assert bytes_from_bits(extracted) == b"rdh"
    np.testing.assert_array_equal(recovered, channel)


def test_payload_is_extracted_exactly_and_image_recovers_for_p_greater_than_z():
    channel = _base_channel(peak=10, neighbor_to_block_zero=11)
    payload = bits_from_bytes(b"hi")

    marked, info = embed_bits(channel, payload)
    extracted, recovered = extract_bits_and_recover(marked)

    assert info.peak == 10
    assert info.zero == 9
    assert extracted == payload
    np.testing.assert_array_equal(recovered, channel)


def test_boundary_pixels_0_and_255_do_not_break_recovery():
    channel = _base_channel(peak=128, neighbor_to_block_zero=127)
    channel[2, 0] = 0
    channel[2, 1] = 255
    payload = bits_from_bytes(b"b")

    marked, _ = embed_bits(channel, payload)
    extracted, recovered = extract_bits_and_recover(marked)

    assert extracted == payload
    np.testing.assert_array_equal(recovered, channel)


def test_empty_payload_works():
    channel = _base_channel(peak=80, neighbor_to_block_zero=79)

    marked, info = embed_bits(channel, [])
    extracted, recovered = extract_bits_and_recover(marked)

    assert info.payload_length == 0
    assert extracted == []
    np.testing.assert_array_equal(recovered, channel)


def test_oversized_payload_is_rejected_clearly():
    channel = _base_channel(peak=50, neighbor_to_block_zero=49, shape=(16, 16))
    payload = [1] * 1000

    with pytest.raises(ValueError, match="too large"):
        embed_bits(channel, payload)


def test_no_zero_point_case_records_coordinates_and_recovers_exactly():
    channel = np.resize(np.arange(256, dtype=np.uint8), (32, 32)).copy()
    channel[0, :16] = np.arange(16, dtype=np.uint8)
    channel[10:21, 10:21] = 100
    payload = bits_from_bytes(b"z")

    points = find_histogram_peak_and_zero(channel)
    assert points.has_true_zero is False

    marked, info = embed_bits(channel, payload)
    extracted, recovered = extract_bits_and_recover(marked)

    assert info.has_true_zero is False
    assert info.coordinate_count > 0
    assert extracted == payload
    np.testing.assert_array_equal(recovered, channel)


def test_rejects_non_uint8_channel():
    channel = np.zeros((24, 24), dtype=np.int32)

    with pytest.raises(ValueError, match="uint8"):
        embed_bits(channel, [])


def test_rejects_too_narrow_channel_for_first_16_lsb_storage():
    channel = np.zeros((24, 15), dtype=np.uint8)

    with pytest.raises(ValueError, match="16 columns"):
        embed_bits(channel, [])
