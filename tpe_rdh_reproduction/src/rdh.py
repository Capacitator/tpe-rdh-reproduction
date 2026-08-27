"""Section 5.3 histogram-shifting reversible data hiding for one channel.

This module implements only grayscale/channel RDH from Section 5.3, using the
histogram-shifting background from Section 3.2 and Eq. (1). It does not
implement substitution encryption or the full TPE pipeline.

PAPER AMBIGUITY / IMPLEMENTATION DECISION:
The paper records first-row LSB overhead and minimum-point coordinates, but it
does not define a binary metadata format, payload length marker, or coordinate
encoding. This implementation uses a small explicit header so extraction can be
deterministic and exactly reversible:

    payload_length: 32 bits
    coordinate_count: 32 bits
    original first-16 LSBs: 16 bits
    coordinates: row bits + column bits per coordinate
    payload bits: payload_length bits

PAPER AMBIGUITY / IMPLEMENTATION DECISION:
The first 16 top-row pixels are excluded from histogram shifting and embedding.
The paper says their LSBs store P and Z and that extraction skips this LSB
portion; it does not fully specify whether these pixels participate in shifting.
Excluding them makes the metadata pixels exactly recoverable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

import numpy as np


Coordinate = Tuple[int, int]


@dataclass(frozen=True)
class HistogramPoints:
    """Peak/zero selection result for histogram shifting."""

    peak: int
    zero: int
    has_true_zero: bool


@dataclass(frozen=True)
class RDHEmbeddingInfo:
    """Debug metadata returned by embedding.

    Extraction does not require this object; P and Z are stored in the marked
    image and the rest of the metadata is embedded in the histogram.
    """

    peak: int
    zero: int
    payload_length: int
    coordinate_count: int
    embedded_bit_count: int
    has_true_zero: bool


def bits_from_bytes(data: bytes) -> List[int]:
    """Convert bytes to a big-endian bit list for embedding payload text/data."""

    bits: List[int] = []
    for value in data:
        bits.extend(_int_to_bits(value, 8))
    return bits


def bytes_from_bits(bits: Sequence[int]) -> bytes:
    """Convert a big-endian bit list back to bytes.

    The bit count must be byte-aligned. Tests use this for readable payloads;
    the RDH core itself accepts arbitrary bit payloads.
    """

    if len(bits) % 8 != 0:
        raise ValueError("bit count must be divisible by 8")
    values = [_bits_to_int(bits[index : index + 8]) for index in range(0, len(bits), 8)]
    return bytes(values)


def find_histogram_peak_and_zero(channel: np.ndarray) -> HistogramPoints:
    """Find the histogram peak P and zero point Z for one uint8 channel.

    Args:
        channel: 2D `uint8` grayscale/channel image.

    Returns:
        `HistogramPoints(peak=P, zero=Z, has_true_zero=...)`.

    Paper reference:
        Section 3.2.1 and Section 5.3. P is the grayscale value with maximum
        count. Z is a grayscale value with zero count; if none exists, the
        minimum-count point is selected.
    """

    _validate_channel(channel)
    mask = _embedding_mask(channel.shape)
    return _find_histogram_peak_and_zero_from_values(channel[mask])


def embed_bits(channel: np.ndarray, payload_bits: Sequence[int]) -> Tuple[np.ndarray, RDHEmbeddingInfo]:
    """Embed payload bits in one grayscale/channel image using histogram shifting.

    Args:
        channel: 2D `uint8` carrier image. In the full paper pipeline this is
            the permutation-encrypted image from Section 5.2.
        payload_bits: Sequence of 0/1 payload bits to embed.

    Returns:
        `(marked_channel, info)`. `marked_channel` stores P/Z in the first 16
        top-row LSBs and carries the overhead + payload in histogram changes.

    Paper reference:
        Section 5.3 uses histogram shifting and Eq. (1) to embed bits at P:
        P represents bit 0; P+1 or P-1 represents bit 1 depending on P/Z.
    """

    _validate_channel(channel)
    payload = _validate_bits(payload_bits)
    marked = channel.copy()
    mask = _embedding_mask(marked.shape)

    points = _find_histogram_peak_and_zero_from_values(marked[mask])
    coordinates: List[Coordinate] = []

    if not points.has_true_zero:
        coordinates = _prepare_minimum_point_as_zero(marked, mask, points)

    first_lsb_bits = _read_first_16_lsb(marked)
    metadata_and_payload = _pack_metadata_and_payload(
        payload_bits=payload,
        original_first_lsb_bits=first_lsb_bits,
        coordinates=coordinates,
        shape=marked.shape,
    )

    capacity = int(np.count_nonzero(marked[mask] == points.peak))
    if len(metadata_and_payload) > capacity:
        raise ValueError(
            "payload is too large for histogram peak capacity "
            f"({len(metadata_and_payload)} bits needed, {capacity} available)"
        )

    _shift_histogram_to_create_embedding_bin(marked, mask, points.peak, points.zero)
    _embed_stream_at_peak(marked, mask, points.peak, points.zero, metadata_and_payload)
    _write_peak_and_zero_to_first_16_lsb(marked, points.peak, points.zero)

    info = RDHEmbeddingInfo(
        peak=points.peak,
        zero=points.zero,
        payload_length=len(payload),
        coordinate_count=len(coordinates),
        embedded_bit_count=len(metadata_and_payload),
        has_true_zero=points.has_true_zero,
    )
    return marked, info


def extract_bits_and_recover(marked_channel: np.ndarray) -> Tuple[List[int], np.ndarray]:
    """Extract payload bits and exactly recover the original grayscale/channel image.

    Args:
        marked_channel: Output from `embed_bits`.

    Returns:
        `(payload_bits, recovered_channel)`.

    Paper reference:
        Section 3.2.2 and Section 5.5. First read P/Z from the first 16 top-row
        LSBs, extract bits from P and P+1/P-1 values, restore overhead, and
        reverse the histogram shift.
    """

    _validate_channel(marked_channel)
    recovered = marked_channel.copy()
    mask = _embedding_mask(recovered.shape)
    peak, zero = _read_peak_and_zero_from_first_16_lsb(recovered)

    header_bits = _extract_n_bits_from_peak_region(recovered, mask, peak, zero, 80)
    payload_length = _bits_to_int(header_bits[0:32])
    coordinate_count = _bits_to_int(header_bits[32:64])
    original_first_lsb_bits = header_bits[64:80]

    coord_bit_count = _coordinate_bit_count(recovered.shape) * coordinate_count
    remaining_count = coord_bit_count + payload_length
    remaining_bits = _extract_n_bits_from_peak_region(
        recovered, mask, peak, zero, 80 + remaining_count
    )[80:]

    coordinate_bits = remaining_bits[:coord_bit_count]
    payload_bits = remaining_bits[coord_bit_count:]
    coordinates = _decode_coordinates(coordinate_bits, coordinate_count, recovered.shape)

    # Restoring the shifted histogram removes both the space-reserving shift and
    # Eq. (1)-style bit changes: P+1/P-1 values that carried bit 1 return to P.
    _recover_shifted_histogram(recovered, mask, peak, zero)
    _restore_minimum_point_coordinates(recovered, coordinates, zero)
    _restore_first_16_lsb(recovered, original_first_lsb_bits)

    return payload_bits, recovered


def _validate_channel(channel: np.ndarray) -> None:
    if channel.ndim != 2:
        raise ValueError("RDH currently supports one 2D grayscale/channel image")
    if channel.dtype != np.uint8:
        raise ValueError("channel must have dtype uint8")
    if channel.shape[0] < 1 or channel.shape[1] < 16:
        raise ValueError("channel must have at least one row and 16 columns")


def _validate_bits(bits: Sequence[int]) -> List[int]:
    result = [int(bit) for bit in bits]
    if any(bit not in (0, 1) for bit in result):
        raise ValueError("payload_bits must contain only 0 and 1")
    return result


def _embedding_mask(shape: Tuple[int, int]) -> np.ndarray:
    mask = np.ones(shape, dtype=bool)
    mask[0, :16] = False
    return mask


def _find_histogram_peak_and_zero_from_values(values: np.ndarray) -> HistogramPoints:
    histogram = np.bincount(values.reshape(-1), minlength=256)
    peak_candidates = np.flatnonzero(histogram == histogram.max())
    zero_candidates = np.flatnonzero(histogram == 0)

    if zero_candidates.size:
        peak, zero = _nearest_pair(peak_candidates, zero_candidates)
        return HistogramPoints(int(peak), int(zero), True)

    # The paper says to choose a minimum-count point when no zero exists.
    # We avoid choosing P itself or 0 because the described "set to 0" step
    # would otherwise fail to create a useful, recoverable empty bin.
    min_count = histogram[[value for value in range(1, 256) if value not in peak_candidates]].min()
    min_candidates = np.array(
        [
            value
            for value in range(1, 256)
            if value not in peak_candidates and histogram[value] == min_count
        ],
        dtype=np.int64,
    )
    peak, zero = _nearest_pair(peak_candidates, min_candidates)
    return HistogramPoints(int(peak), int(zero), False)


def _nearest_pair(left: np.ndarray, right: np.ndarray) -> Tuple[int, int]:
    best_pair = (int(left[0]), int(right[0]))
    best_distance = abs(best_pair[0] - best_pair[1])
    for p_value in left:
        for z_value in right:
            distance = abs(int(p_value) - int(z_value))
            candidate = (int(p_value), int(z_value))
            if distance < best_distance or (
                distance == best_distance and candidate < best_pair
            ):
                best_pair = candidate
                best_distance = distance
    return best_pair


def _prepare_minimum_point_as_zero(
    marked: np.ndarray, mask: np.ndarray, points: HistogramPoints
) -> List[Coordinate]:
    carrier_values = {points.peak}
    if points.peak < points.zero:
        carrier_values.add(points.peak + 1)
    else:
        carrier_values.add(points.peak - 1)
    if 0 in carrier_values:
        raise ValueError(
            "no-zero-point preprocessing would create ambiguous carrier pixels"
        )

    coordinate_array = np.argwhere((marked == points.zero) & mask)
    coordinates = [(int(row), int(col)) for row, col in coordinate_array]

    # Section 5.3 says these minimum-point pixels are recorded as overhead and
    # their grayscale values are set to 0, thereby making the selected Z bin
    # empty for histogram shifting.
    for row, col in coordinates:
        marked[row, col] = 0

    return coordinates


def _shift_histogram_to_create_embedding_bin(
    marked: np.ndarray, mask: np.ndarray, peak: int, zero: int
) -> None:
    if peak < zero:
        shift_mask = (marked > peak) & (marked < zero) & mask
        marked[shift_mask] += 1
    elif peak > zero:
        shift_mask = (marked > zero) & (marked < peak) & mask
        marked[shift_mask] -= 1
    else:
        raise ValueError("peak and zero must be different")


def _embed_stream_at_peak(
    marked: np.ndarray, mask: np.ndarray, peak: int, zero: int, bits: Sequence[int]
) -> None:
    bit_index = 0
    one_value = peak + 1 if peak < zero else peak - 1

    for row, col in _scan_coordinates(mask):
        if bit_index >= len(bits):
            break
        if marked[row, col] == peak:
            if bits[bit_index] == 1:
                marked[row, col] = one_value
            bit_index += 1

    if bit_index != len(bits):
        raise RuntimeError("internal error: capacity check passed but embedding failed")


def _recover_shifted_histogram(
    recovered: np.ndarray, mask: np.ndarray, peak: int, zero: int
) -> None:
    if peak < zero:
        recover_mask = (recovered > peak) & (recovered <= zero) & mask
        recovered[recover_mask] -= 1
    elif peak > zero:
        recover_mask = (recovered >= zero) & (recovered < peak) & mask
        recovered[recover_mask] += 1
    else:
        raise ValueError("peak and zero must be different")


def _extract_n_bits_from_peak_region(
    marked: np.ndarray, mask: np.ndarray, peak: int, zero: int, bit_count: int
) -> List[int]:
    bits: List[int] = []
    one_value = peak + 1 if peak < zero else peak - 1

    for row, col in _scan_coordinates(mask):
        value = int(marked[row, col])
        if value == peak:
            bits.append(0)
        elif value == one_value:
            bits.append(1)

        if len(bits) == bit_count:
            return bits

    raise ValueError("marked image does not contain enough embedded bits")


def _scan_coordinates(mask: np.ndarray) -> Iterable[Coordinate]:
    for row in range(mask.shape[0]):
        for col in range(mask.shape[1]):
            if mask[row, col]:
                yield row, col


def _pack_metadata_and_payload(
    payload_bits: Sequence[int],
    original_first_lsb_bits: Sequence[int],
    coordinates: Sequence[Coordinate],
    shape: Tuple[int, int],
) -> List[int]:
    bits: List[int] = []
    bits.extend(_int_to_bits(len(payload_bits), 32))
    bits.extend(_int_to_bits(len(coordinates), 32))
    bits.extend(original_first_lsb_bits)
    bits.extend(_encode_coordinates(coordinates, shape))
    bits.extend(payload_bits)
    return bits


def _encode_coordinates(coordinates: Sequence[Coordinate], shape: Tuple[int, int]) -> List[int]:
    row_bits, col_bits = _coordinate_bit_widths(shape)
    bits: List[int] = []
    for row, col in coordinates:
        bits.extend(_int_to_bits(row, row_bits))
        bits.extend(_int_to_bits(col, col_bits))
    return bits


def _decode_coordinates(
    bits: Sequence[int], coordinate_count: int, shape: Tuple[int, int]
) -> List[Coordinate]:
    row_bits, col_bits = _coordinate_bit_widths(shape)
    step = row_bits + col_bits
    coordinates: List[Coordinate] = []
    for index in range(coordinate_count):
        start = index * step
        row = _bits_to_int(bits[start : start + row_bits])
        col = _bits_to_int(bits[start + row_bits : start + step])
        coordinates.append((row, col))
    return coordinates


def _coordinate_bit_widths(shape: Tuple[int, int]) -> Tuple[int, int]:
    height, width = shape
    return max(1, (height - 1).bit_length()), max(1, (width - 1).bit_length())


def _coordinate_bit_count(shape: Tuple[int, int]) -> int:
    row_bits, col_bits = _coordinate_bit_widths(shape)
    return row_bits + col_bits


def _restore_minimum_point_coordinates(
    recovered: np.ndarray, coordinates: Sequence[Coordinate], zero: int
) -> None:
    for row, col in coordinates:
        recovered[row, col] = zero


def _read_first_16_lsb(channel: np.ndarray) -> List[int]:
    return [int(value) & 1 for value in channel[0, :16]]


def _restore_first_16_lsb(channel: np.ndarray, bits: Sequence[int]) -> None:
    for col, bit in enumerate(bits):
        channel[0, col] = (int(channel[0, col]) & 0xFE) | int(bit)


def _write_peak_and_zero_to_first_16_lsb(channel: np.ndarray, peak: int, zero: int) -> None:
    bits = _int_to_bits(peak, 8) + _int_to_bits(zero, 8)
    for col, bit in enumerate(bits):
        channel[0, col] = (int(channel[0, col]) & 0xFE) | bit


def _read_peak_and_zero_from_first_16_lsb(channel: np.ndarray) -> Tuple[int, int]:
    bits = _read_first_16_lsb(channel)
    return _bits_to_int(bits[:8]), _bits_to_int(bits[8:])


def _int_to_bits(value: int, width: int) -> List[int]:
    if value < 0 or value >= 2**width:
        raise ValueError(f"value {value} does not fit in {width} bits")
    return [(value >> shift) & 1 for shift in range(width - 1, -1, -1)]


def _bits_to_int(bits: Sequence[int]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | int(bit)
    return value
