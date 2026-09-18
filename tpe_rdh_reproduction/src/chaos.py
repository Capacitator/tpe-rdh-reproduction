"""Chaotic maps from Section 4 of the paper.

This module implements the 2D-CSM material from Section 4 and the
chaotic-matrix generation step from Section 5.1:

- Eq. (2): Cubic map
- Eq. (3): Sinusoidal map
- Eq. (4): coupled two-dimensional CSM map
- Section 5.1: derive key/image-dependent chaotic matrices `Upsilon_P` and
  `Upsilon_S`

The paper requires key reuse across images to remain secure: the same secret
key applied to different images must still generate different chaotic
sequences. The accessible text specifies the `T -> T_tau -> kappa_2`
diversification behavior but not the exact byte-level conversion rules. This
module uses a documented SHA-256/fixed-field convention to implement that
required key-reuse property.
"""

from __future__ import annotations

import hashlib
import math
from typing import Tuple, Union

import numpy as np


PAPER_UNSPECIFIED_SECTION5_PARAMETERS = {
    "key_T_kappa_convention": (
        "IMPLEMENTATION DECISION: a 256-bit key is split into four 64-bit "
        "fields. The first two fields are normalized to x0 and y0 in (0, 1), "
        "the third and fourth fields define r1 and r2 in [1, 100], and "
        "kappa_1 is derived from SHA-256(key || b'kappa_1') as 128..1151. "
        "Image identifier T is hashed as SHA-256(T) and mapped to positive "
        "T_tau in 1..1024. kappa_2 is derived from the key, complete image "
        "identifier, and stage-1 chaotic output as 1..1024. These ranges "
        "keep experiments reproducible and bounded while ensuring T_tau "
        "collisions do not discard the remaining identifier information."
    ),
    "matrix_independence": (
        "PAPER AMBIGUITY: Section 5.1 says two independent chaotic matrices "
        "are generated; the accessible text does not fully specify whether "
        "they are the x/y sequences from one 2D-CSM run or separate runs."
    ),
}

KeyLike = Union[bytes, bytearray, int]
IdentifierLike = Union[bytes, bytearray, str, int]

KEY_BITS = 256
KEY_BYTES = KEY_BITS // 8
KAPPA_1_MIN = 128
KAPPA_1_SPAN = 1024
T_TAU_SPAN = 1024
KAPPA_2_SPAN = 1024
R_MIN = 1.0
R_MAX = 100.0


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
    key: KeyLike,
    image_identifier: IdentifierLike,
) -> Tuple[np.ndarray, np.ndarray]:
    """Generate Section 5.1 key/image-dependent chaotic matrices.

    Section 5.1 says the valid chaotic sequences are reshaped into two
    matrices: `Upsilon_P`, which later controls block permutation, and
    `Upsilon_S`, which later controls substitution offsets.

    The paper requires per-image diversification under key reuse by deriving
    `kappa_2` through `T` and `T_tau`, but it does not specify the exact
    byte-level conversion convention. This implementation uses:

    1. split the 256-bit key into four 64-bit fields;
    2. map fields 1 and 2 to `x0` and `y0` in `(0, 1)`;
    3. map fields 3 and 4 to `r1` and `r2` in `[1, 100]`;
    4. derive `kappa_1` from `SHA-256(key || b"kappa_1")`;
    5. derive positive `T_tau` from `SHA-256(image_identifier)`;
    6. run Eq. (4) for `kappa_1 + T_tau` iterations;
    7. derive positive `kappa_2` from the key, complete image identifier, and
       resulting chaotic state;
    8. restart from `(x0, y0)`, run `kappa_1 + kappa_2 + M*N`
       iterations, discard `kappa_1 + kappa_2`, and reshape the remainder.

    Args:
        height: Image/channel height `M`.
        width: Image/channel width `N`.
        key: 256-bit secret key as exactly 32 bytes or an integer in
            `[0, 2**256)`.
        image_identifier: Per-image identifier `T`, such as image bytes,
            a filename, or a stored identifier. The same value is required
            during decryption.

    Returns:
        `(Upsilon_P, Upsilon_S)`, both shaped `(height, width)`.

    Paper reference:
        Section 5.1. `Upsilon_P` is used later by Section 5.2 permutation;
        `Upsilon_S` is used later by Section 5.4 substitution.
    """

    if height <= 0 or width <= 0:
        raise ValueError("height and width must be positive")

    matrix_size = height * width
    key_bytes = _key_to_32_bytes(key)
    t_bytes = _identifier_to_bytes(image_identifier)
    x0, y0, r1, r2, kappa_1 = derive_csm_parameters_from_key(key_bytes)
    t_tau = derive_t_tau(t_bytes)

    stage1_iterations = kappa_1 + t_tau
    stage1_x, stage1_y = generate_2d_csm(
        x0=x0,
        y0=y0,
        r1=r1,
        r2=r2,
        iterations=stage1_iterations,
    )
    kappa_2 = derive_kappa_2(
        stage1_x[-1],
        stage1_y[-1],
        key=key_bytes,
        image_identifier=t_bytes,
    )
    discard_count = kappa_1 + kappa_2

    # Section 5.1 restarts from the key-derived initial state, discards the
    # transient/image-dependent prefix, and reshapes the retained x/y outputs.
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


def derive_csm_parameters_from_key(key: KeyLike) -> Tuple[float, float, float, float, int]:
    """Return `(x0, y0, r1, r2, kappa_1)` from a 256-bit key.

    This is an implementation convention for the Section 5.1 key schedule.
    It is deterministic and uses every key bit either directly in the four
    fixed-width fields or through the SHA-256-derived `kappa_1`.
    """

    key_bytes = _key_to_32_bytes(key)
    fields = [
        int.from_bytes(key_bytes[index : index + 8], "big")
        for index in range(0, KEY_BYTES, 8)
    ]
    denominator = float(2**64)
    x0 = (fields[0] + 0.5) / denominator
    y0 = (fields[1] + 0.5) / denominator
    r_span = R_MAX - R_MIN
    r_denominator = float(2**64 - 1)
    r1 = R_MIN + r_span * (fields[2] / r_denominator)
    r2 = R_MIN + r_span * (fields[3] / r_denominator)
    kappa_digest = hashlib.sha256(key_bytes + b"kappa_1").digest()
    kappa_1 = KAPPA_1_MIN + int.from_bytes(kappa_digest[:4], "big") % KAPPA_1_SPAN
    return x0, y0, r1, r2, kappa_1


def derive_t_tau(image_identifier: IdentifierLike) -> int:
    """Return a positive bounded `T_tau` from image identifier `T`."""

    t_bytes = _identifier_to_bytes(image_identifier)
    digest = hashlib.sha256(t_bytes).digest()
    return 1 + int.from_bytes(digest[:4], "big") % T_TAU_SPAN


def derive_kappa_2(
    x_value: float,
    y_value: float,
    key: KeyLike,
    image_identifier: IdentifierLike,
) -> int:
    """Return a positive bounded, fully context-bound `kappa_2`.

    Including the complete identifier prevents distinct identifiers that map
    to the same bounded ``T_tau`` from automatically producing the same final
    matrices. The key and domain tag keep this derivation separate from the
    other SHA-256-based schedule steps.
    """

    key_bytes = _key_to_32_bytes(key)
    identifier_bytes = _identifier_to_bytes(image_identifier)
    material = (
        b"tpe-rdh:kappa_2:v1\x00"
        + key_bytes
        + len(identifier_bytes).to_bytes(8, "big")
        + identifier_bytes
        + f"{x_value:.17g},{y_value:.17g}".encode("ascii")
    )
    digest = hashlib.sha256(material).digest()
    return 1 + int.from_bytes(digest[:8], "big") % KAPPA_2_SPAN


def _key_to_32_bytes(key: KeyLike) -> bytes:
    if isinstance(key, int):
        if key < 0 or key >= 2**KEY_BITS:
            raise ValueError("key integer must be in [0, 2**256)")
        return key.to_bytes(KEY_BYTES, "big")
    if isinstance(key, (bytes, bytearray)):
        key_bytes = bytes(key)
        if len(key_bytes) != KEY_BYTES:
            raise ValueError("key must be exactly 32 bytes (256 bits)")
        return key_bytes
    raise TypeError("key must be 32 bytes or an integer in [0, 2**256)")


def _identifier_to_bytes(image_identifier: IdentifierLike) -> bytes:
    if isinstance(image_identifier, str):
        return image_identifier.encode("utf-8")
    if isinstance(image_identifier, int):
        if image_identifier < 0:
            raise ValueError("image_identifier integer must be non-negative")
        length = max(1, (image_identifier.bit_length() + 7) // 8)
        return image_identifier.to_bytes(length, "big")
    if isinstance(image_identifier, (bytes, bytearray)):
        identifier = bytes(image_identifier)
        if not identifier:
            raise ValueError("image_identifier must not be empty")
        return identifier
    raise TypeError("image_identifier must be bytes, str, or non-negative int")
