"""Section 5.4 substitution encryption.

This module implements the pair-wise sum-preserving substitution step from
Section 5.4 only. It does not implement RDH, permutation, or the full pipeline.

Implemented paper equations:

- Eq. (6): chaotic pair offset `delta`
- Eq. (7): pixel pair -> same-sum index `eta`
- Eq. (8): modular index encryption
- Eq. (9): count of valid same-sum pixel pairs
- Eq. (10): encrypted index -> encrypted same-sum pixel pair

PAPER AMBIGUITY / IMPLEMENTATION DECISION:
The paper states that pixels and chaotic values inside each `b x b` thumbnail
block are paired, but does not specify pairing order. For the optional block
helpers in this module, pairs are taken in row-major flattened order:
positions `(0, 1)`, `(2, 3)`, and so on inside each block.

PAPER AMBIGUITY / IMPLEMENTATION DECISION:
The paper defines `vartheta` as a predefined amplification coefficient with
`vartheta >> 1`, but gives no numeric value. This module requires the caller to
pass `vartheta`; demos/tests use clearly marked non-paper demo values.
"""

from __future__ import annotations

import math
from typing import Iterator, Tuple

import numpy as np


PixelPair = Tuple[int, int]


def same_sum_pair_count(s_tau: int, d: int = 255) -> int:
    """Return `|Theta_sum(s_tau)|` from Eq. (9).

    Args:
        s_tau: Sum of a two-pixel group.
        d: Maximum pixel value. The paper uses `d = 255`.

    Returns:
        Number of valid pairs `(tau1, tau2)` with `0 <= tau_i <= d` and
        `tau1 + tau2 = s_tau`.

    Paper reference:
        Section 5.4, Eq. (9).
    """

    _validate_sum_and_d(s_tau, d)
    if s_tau <= d:
        return s_tau + 1
    return 2 * d - s_tau + 1


def pair_to_index(tau1: int, tau2: int, d: int = 255) -> int:
    """Map a two-pixel group to its same-sum index `eta` using Eq. (7).

    The index identifies which valid pair was selected among all pairs with
    the same sum. Section 5.4 encrypts this index instead of the sum so the
    output pair keeps the same thumbnail/block contribution.

    Args:
        tau1: First pixel value.
        tau2: Second pixel value.
        d: Maximum pixel value. The paper uses `d = 255`.

    Returns:
        Same-sum index `eta`.

    Paper reference:
        Section 5.4, Eq. (7).
    """

    _validate_pixel(tau1, d)
    _validate_pixel(tau2, d)
    s_tau = tau1 + tau2
    if s_tau <= d:
        return tau1
    return tau1 - s_tau + d


def index_to_pair(eta: int, s_tau: int, d: int = 255) -> PixelPair:
    """Map a same-sum index back to a pixel pair using Eq. (10).

    Args:
        eta: Same-sum index. During encryption this is `eta_e`; during
            decryption it is the recovered original `eta`.
        s_tau: Required pair sum.
        d: Maximum pixel value. The paper uses `d = 255`.

    Returns:
        Pixel pair whose values are both in `[0, d]` and sum to `s_tau`.

    Paper reference:
        Section 5.4, Eq. (10).
    """

    _validate_sum_and_d(s_tau, d)
    count = same_sum_pair_count(s_tau, d)
    if eta < 0 or eta >= count:
        raise ValueError("eta is outside the valid range for this same-sum set")

    if s_tau <= d:
        return int(eta), int(s_tau - eta)
    return int(s_tau - d + eta), int(d - eta)


def chaotic_pair_delta(gamma1: float, gamma2: float, vartheta: float) -> int:
    """Calculate the chaotic offset `delta` from Eq. (6).

    Args:
        gamma1: First non-negative chaotic value from `Upsilon_S'`.
        gamma2: Second non-negative chaotic value from `Upsilon_S'`.
        vartheta: Predefined amplification coefficient. The paper states
            `vartheta >> 1` but does not provide a numeric value.

    Returns:
        Integer offset `floor((gamma1 + gamma2) * vartheta)`.

    Paper reference:
        Section 5.4, Eq. (6).
    """

    _validate_vartheta(vartheta)
    if not (math.isfinite(gamma1) and math.isfinite(gamma2)):
        raise ValueError("gamma values must be finite")
    if gamma1 < 0 or gamma2 < 0:
        raise ValueError("gamma values must come from non-negative Upsilon_S'")
    return math.floor((gamma1 + gamma2) * vartheta)


def encrypt_pair(
    tau1: int,
    tau2: int,
    gamma1: float,
    gamma2: float,
    vartheta: float,
    d: int = 255,
) -> PixelPair:
    """Encrypt one two-pixel group with Eq. (6)-Eq. (10).

    Args:
        tau1: First plaintext/marked pixel value.
        tau2: Second plaintext/marked pixel value.
        gamma1: First matching chaotic value from `Upsilon_S'`.
        gamma2: Second matching chaotic value from `Upsilon_S'`.
        vartheta: Amplification coefficient required by Eq. (6).
        d: Maximum pixel value. The paper uses `d = 255`.

    Returns:
        Encrypted pair `(tau1_e, tau2_e)` with the exact same sum as the input.

    Paper reference:
        Section 5.4. Eq. (7) indexes the same-sum pair; Eq. (8) shifts the
        index by chaotic `delta`; Eq. (10) maps back to a valid pixel pair.
    """

    s_tau = _validate_pair_and_get_sum(tau1, tau2, d)
    eta = pair_to_index(tau1, tau2, d)
    delta = chaotic_pair_delta(gamma1, gamma2, vartheta)
    count = same_sum_pair_count(s_tau, d)
    eta_e = (eta + delta) % count
    return index_to_pair(eta_e, s_tau, d)


def decrypt_pair(
    tau1_e: int,
    tau2_e: int,
    gamma1: float,
    gamma2: float,
    vartheta: float,
    d: int = 255,
) -> PixelPair:
    """Reverse `encrypt_pair` for one two-pixel group.

    Args:
        tau1_e: First encrypted pixel value.
        tau2_e: Second encrypted pixel value.
        gamma1: First matching chaotic value used during encryption.
        gamma2: Second matching chaotic value used during encryption.
        vartheta: Same amplification coefficient used during encryption.
        d: Maximum pixel value. The paper uses `d = 255`.

    Returns:
        Original pair `(tau1, tau2)`.

    Paper reference:
        Section 5.5 describes extracting `eta_e`, applying the decryption
        algorithm to recover `eta`, then reconstructing the original group.
        The subtraction below is the direct inverse of Eq. (8).
    """

    s_tau = _validate_pair_and_get_sum(tau1_e, tau2_e, d)
    eta_e = pair_to_index(tau1_e, tau2_e, d)
    delta = chaotic_pair_delta(gamma1, gamma2, vartheta)
    count = same_sum_pair_count(s_tau, d)
    eta = (eta_e - delta) % count
    return index_to_pair(eta, s_tau, d)


def substitute_channel_blocks(
    channel: np.ndarray,
    upsilon_s: np.ndarray,
    block_size: int,
    vartheta: float,
    d: int = 255,
) -> np.ndarray:
    """Apply Section 5.4 substitution to one grayscale/channel image.

    Args:
        channel: 2D `uint8` channel to substitute.
        upsilon_s: Section 5.1 substitution-control matrix, same shape as
            `channel`.
        block_size: Thumbnail block size `b`.
        vartheta: Amplification coefficient required by Eq. (6).
        d: Maximum pixel value. The paper uses `d = 255`.

    Returns:
        Substituted channel with the same shape and dtype.

    `abs(upsilon_s)` is used because Section 5.4 first converts `Upsilon_S` to
    non-negative `Upsilon_S'` before pairing chaotic values.
    """

    _validate_channel_inputs(channel, upsilon_s, block_size, vartheta)
    return _transform_channel_blocks(channel, upsilon_s, block_size, vartheta, d, True)


def inverse_substitute_channel_blocks(
    substituted_channel: np.ndarray,
    upsilon_s: np.ndarray,
    block_size: int,
    vartheta: float,
    d: int = 255,
) -> np.ndarray:
    """Reverse `substitute_channel_blocks` for one grayscale/channel image."""

    _validate_channel_inputs(substituted_channel, upsilon_s, block_size, vartheta)
    return _transform_channel_blocks(
        substituted_channel, upsilon_s, block_size, vartheta, d, False
    )


def _transform_channel_blocks(
    channel: np.ndarray,
    upsilon_s: np.ndarray,
    block_size: int,
    vartheta: float,
    d: int,
    encrypting: bool,
) -> np.ndarray:
    result = np.empty_like(channel)
    upsilon_nonnegative = np.abs(upsilon_s)

    for row, col in _block_origins(channel.shape[0], channel.shape[1], block_size):
        pixel_flat = channel[row : row + block_size, col : col + block_size].reshape(-1)
        gamma_flat = upsilon_nonnegative[
            row : row + block_size, col : col + block_size
        ].reshape(-1)
        output_flat = np.empty_like(pixel_flat)

        for index in range(0, pixel_flat.size, 2):
            tau1 = int(pixel_flat[index])
            tau2 = int(pixel_flat[index + 1])
            gamma1 = float(gamma_flat[index])
            gamma2 = float(gamma_flat[index + 1])
            if encrypting:
                out1, out2 = encrypt_pair(tau1, tau2, gamma1, gamma2, vartheta, d)
            else:
                out1, out2 = decrypt_pair(tau1, tau2, gamma1, gamma2, vartheta, d)
            output_flat[index] = out1
            output_flat[index + 1] = out2

        result[row : row + block_size, col : col + block_size] = output_flat.reshape(
            block_size, block_size
        )

    return result


def _block_origins(height: int, width: int, block_size: int) -> Iterator[Tuple[int, int]]:
    for row in range(0, height, block_size):
        for col in range(0, width, block_size):
            yield row, col


def _validate_channel_inputs(
    channel: np.ndarray, upsilon_s: np.ndarray, block_size: int, vartheta: float
) -> None:
    if channel.ndim != 2:
        raise ValueError("substitution currently supports one 2D channel")
    if channel.dtype != np.uint8:
        raise ValueError("channel must have dtype uint8")
    if upsilon_s.shape != channel.shape:
        raise ValueError("upsilon_s must match channel shape")
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if block_size * block_size % 2 != 0:
        raise ValueError("block_size must contain an even number of pixels")
    if channel.shape[0] % block_size != 0 or channel.shape[1] % block_size != 0:
        raise ValueError("channel dimensions must be divisible by block_size")
    _validate_vartheta(vartheta)


def _validate_pair_and_get_sum(tau1: int, tau2: int, d: int) -> int:
    _validate_pixel(tau1, d)
    _validate_pixel(tau2, d)
    return tau1 + tau2


def _validate_pixel(value: int, d: int) -> None:
    if not isinstance(value, (int, np.integer)):
        raise ValueError("pixel values must be integers")
    _validate_d(d)
    if value < 0 or value > d:
        raise ValueError(f"pixel value must be in 0..{d}")


def _validate_sum_and_d(s_tau: int, d: int) -> None:
    if not isinstance(s_tau, (int, np.integer)):
        raise ValueError("s_tau must be an integer")
    _validate_d(d)
    if s_tau < 0 or s_tau > 2 * d:
        raise ValueError(f"s_tau must be in 0..{2 * d}")


def _validate_d(d: int) -> None:
    if not isinstance(d, (int, np.integer)) or d <= 0:
        raise ValueError("d must be a positive integer")


def _validate_vartheta(vartheta: float) -> None:
    if not math.isfinite(vartheta) or vartheta <= 0:
        raise ValueError("vartheta must be a positive finite number")

