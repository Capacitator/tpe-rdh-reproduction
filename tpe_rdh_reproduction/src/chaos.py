"""Chaotic maps from Section 4 of the paper.

This module implements the 2D-CSM material from Section 4 and the narrow
chaotic-matrix reshaping step from Section 5.1:

- Eq. (2): Cubic map
- Eq. (3): Sinusoidal map
- Eq. (4): coupled two-dimensional CSM map
- Section 5.1: reshape two valid chaotic sequences into `Upsilon_P` and
  `Upsilon_S`

It intentionally does not implement Section 5 key conversion, `T`, `T_tau`,
`kappa_1`, `kappa_2`, permutation, RDH, substitution, or pipeline logic.
"""

from __future__ import annotations

import math
from typing import Tuple

import numpy as np


PAPER_UNSPECIFIED_SECTION5_PARAMETERS = {
    "key_conversion": (
        "PAPER AMBIGUITY: the paper claims a 256-bit key space but does not "
        "state how the key is converted into x0, y0, r1, r2, T, or discards."
    ),
    "kappa_1": (
        "PAPER AMBIGUITY: Section 5.1 discards kappa_1 transient values but "
        "does not give a numeric value or selection rule."
    ),
    "T_and_T_tau": (
        "PAPER AMBIGUITY: Section 5.1 uses an image identifier T and a "
        "positive integer T_tau, but does not define the conversion."
    ),
    "kappa_2": (
        "PAPER AMBIGUITY: Section 5.1 derives kappa_2 from chaotic output, "
        "but does not specify which output or integer conversion."
    ),
    "matrix_independence": (
        "PAPER AMBIGUITY: Section 5.1 says two independent chaotic matrices "
        "are generated; the accessible text does not fully specify whether "
        "they are the x/y sequences from one 2D-CSM run or separate runs."
    ),
}


def cubic_map(x_n: float, r1: float) -> float:
    """Return one Cubic-map iteration from Eq. (2).

    Args:
        x_n: Current scalar state.
        r1: Cubic-map control parameter.

    Returns:
        The next scalar state, `x_{n+1} = r1 * x_n * (1 - x_n^2)`.

    Paper reference:
        Section 4.1, Eq. (2).
    """

    return r1 * x_n * (1.0 - x_n**2)


def sinusoidal_map(x_n: float, r2: float) -> float:
    """Return one Sinusoidal-map iteration from Eq. (3).

    Args:
        x_n: Current scalar state.
        r2: Sinusoidal-map control parameter.

    Returns:
        The next scalar state, `x_{n+1} = r2 * x_n^2 * sin(pi * x_n)`.

    Paper reference:
        Section 4.1, Eq. (3).
    """

    return r2 * x_n**2 * math.sin(math.pi * x_n)


def csm_2d_step(x_n: float, y_n: float, r1: float, r2: float) -> Tuple[float, float]:
    """Return one coupled 2D-CSM iteration from Eq. (4).

    Eq. (4) couples the Cubic-map term of one variable with the Sinusoidal-map
    term of the other variable, then wraps each update in `sin(pi * ...)`.
    That final sine is why the generated states remain bounded even when the
    paper's example control parameters are large (`r1 = r2 = 50`).

    Args:
        x_n: Current x state.
        y_n: Current y state.
        r1: Cubic-map control parameter.
        r2: Sinusoidal-map control parameter.

    Returns:
        `(x_{n+1}, y_{n+1})` according to Section 4.1, Eq. (4).
    """

    x_argument = (
        2.595 * r1 * r2 * x_n * (1.0 - x_n**2)
        + r2 * y_n**2 * math.sin(math.pi * y_n)
    )
    y_argument = (
        2.595 * r1 * r2 * y_n * (1.0 - y_n**2)
        + r2 * x_n**2 * math.sin(math.pi * x_n)
    )

    return math.sin(math.pi * x_argument), math.sin(math.pi * y_argument)


def generate_2d_csm(
    x0: float,
    y0: float,
    r1: float,
    r2: float,
    iterations: int,
    *,
    include_initial: bool = False,
) -> Tuple[np.ndarray, np.ndarray]:
    """Generate x and y sequences with the paper's 2D-CSM map.

    Args:
        x0: Initial x state. The paper uses `0.3` in its examples.
        y0: Initial y state. The paper uses `0.2` in its examples.
        r1: Cubic-map control parameter. The paper uses `50` in its examples.
        r2: Sinusoidal-map control parameter. The paper uses `50` in its examples.
        iterations: Number of Eq. (4) updates to compute.
        include_initial: If true, prepend `(x0, y0)` before generated updates.

    Returns:
        Two NumPy arrays `(x_values, y_values)`. With `include_initial=False`,
        both arrays have length `iterations`; with `include_initial=True`, both
        arrays have length `iterations + 1`.

    Paper reference:
        Section 4.1, Eq. (4). Section 4.2 uses `5000` iterations for the
        trajectory diagram with `x0 = 0.3`, `y0 = 0.2`, and `r1 = r2 = 50`.
    """

    if iterations < 0:
        raise ValueError("iterations must be non-negative")

    output_length = iterations + 1 if include_initial else iterations
    x_values = np.empty(output_length, dtype=np.float64)
    y_values = np.empty(output_length, dtype=np.float64)

    x_current = float(x0)
    y_current = float(y0)

    start_index = 0
    if include_initial:
        x_values[0] = x_current
        y_values[0] = y_current
        start_index = 1

    # Each stored value is the result of one deterministic Eq. (4) update.
    # Section 5.1 later reuses these sequences to form chaotic matrices, but
    # discard counts and key-derived parameters are deliberately left outside
    # this Section 4 implementation.
    for index in range(start_index, output_length):
        x_current, y_current = csm_2d_step(x_current, y_current, r1, r2)
        x_values[index] = x_current
        y_values[index] = y_current

    return x_values, y_values


def generate_upsilon_matrices(
    height: int,
    width: int,
    x0: float,
    y0: float,
    r1: float,
    r2: float,
    discard_count: int,
) -> Tuple[np.ndarray, np.ndarray]:
    """Generate Section 5.1 chaotic matrices for a known image shape.

    Section 5.1 says the valid chaotic sequences are reshaped into two
    matrices: `Upsilon_P`, which later controls block permutation, and
    `Upsilon_S`, which later controls substitution offsets. The paper's
    missing `kappa_1`, `T`, `T_tau`, and `kappa_2` details mean this function
    requires a caller-supplied total `discard_count` instead of pretending that
    a paper value exists.

    Args:
        height: Image/channel height `M`.
        width: Image/channel width `N`.
        x0: Initial x state. The paper example uses `0.3`.
        y0: Initial y state. The paper example uses `0.2`.
        r1: Cubic-map control parameter. The paper example uses `50`.
        r2: Sinusoidal-map control parameter. The paper example uses `50`.
        discard_count: Total number of Eq. (4) updates to discard before
            reshaping valid sequence values. This is an explicit experiment
            parameter because the paper does not numerically specify the
            Section 5.1 discard construction.

    Returns:
        `(Upsilon_P, Upsilon_S)`, both shaped `(height, width)`.

    Paper reference:
        Section 5.1. `Upsilon_P` is used later by Section 5.2 permutation;
        `Upsilon_S` is used later by Section 5.4 substitution.
    """

    if height <= 0 or width <= 0:
        raise ValueError("height and width must be positive")
    if discard_count < 0:
        raise ValueError("discard_count must be non-negative")

    matrix_size = height * width

    # We generate enough Eq. (4) states for the explicit discard plus the
    # retained values needed by the two Section 5.1 matrices. The accessible
    # paper text describes two valid 1D chaotic sequences, but leaves the
    # independence construction underspecified; here they are the x/y outputs
    # from the same deterministic 2D-CSM run, and this choice is flagged above.
    x_values, y_values = generate_2d_csm(
        x0=x0,
        y0=y0,
        r1=r1,
        r2=r2,
        iterations=discard_count + matrix_size,
    )

    valid_x = x_values[discard_count:]
    valid_y = y_values[discard_count:]

    upsilon_p = valid_x.reshape((height, width))
    upsilon_s = valid_y.reshape((height, width))

    return upsilon_p, upsilon_s
