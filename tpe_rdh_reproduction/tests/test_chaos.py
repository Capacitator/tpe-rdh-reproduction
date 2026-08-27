import math
from pathlib import Path
import sys

import numpy as np
import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from chaos import (
    cubic_map,
    csm_2d_step,
    generate_2d_csm,
    generate_upsilon_matrices,
    sinusoidal_map,
)


def test_cubic_map_matches_eq_2_formula():
    assert cubic_map(0.3, 50.0) == pytest.approx(50.0 * 0.3 * (1.0 - 0.3**2))


def test_sinusoidal_map_matches_eq_3_formula():
    expected = 50.0 * 0.2**2 * math.sin(math.pi * 0.2)
    assert sinusoidal_map(0.2, 50.0) == pytest.approx(expected)


def test_2d_csm_step_matches_eq_4_formula():
    x0 = 0.3
    y0 = 0.2
    r1 = 50.0
    r2 = 50.0

    expected_x = math.sin(
        math.pi
        * (
            2.595 * r1 * r2 * x0 * (1.0 - x0**2)
            + r2 * y0**2 * math.sin(math.pi * y0)
        )
    )
    expected_y = math.sin(
        math.pi
        * (
            2.595 * r1 * r2 * y0 * (1.0 - y0**2)
            + r2 * x0**2 * math.sin(math.pi * x0)
        )
    )

    x1, y1 = csm_2d_step(x0, y0, r1, r2)

    assert x1 == pytest.approx(expected_x)
    assert y1 == pytest.approx(expected_y)


def test_generate_2d_csm_dimensions_and_finite_values():
    x_values, y_values = generate_2d_csm(0.3, 0.2, 50.0, 50.0, 5000)

    assert x_values.shape == (5000,)
    assert y_values.shape == (5000,)
    assert np.all(np.isfinite(x_values))
    assert np.all(np.isfinite(y_values))


def test_generate_2d_csm_is_deterministic_for_identical_inputs():
    first_x, first_y = generate_2d_csm(0.3, 0.2, 50.0, 50.0, 128)
    second_x, second_y = generate_2d_csm(0.3, 0.2, 50.0, 50.0, 128)

    np.testing.assert_array_equal(first_x, second_x)
    np.testing.assert_array_equal(first_y, second_y)


def test_generate_2d_csm_can_include_initial_state():
    x_values, y_values = generate_2d_csm(
        0.3, 0.2, 50.0, 50.0, 3, include_initial=True
    )

    assert x_values.shape == (4,)
    assert y_values.shape == (4,)
    assert x_values[0] == pytest.approx(0.3)
    assert y_values[0] == pytest.approx(0.2)


def test_generate_2d_csm_rejects_negative_iterations():
    with pytest.raises(ValueError, match="iterations"):
        generate_2d_csm(0.3, 0.2, 50.0, 50.0, -1)


def test_generate_upsilon_matrices_dimensions_and_finite_values():
    upsilon_p, upsilon_s = generate_upsilon_matrices(
        height=8,
        width=8,
        x0=0.3,
        y0=0.2,
        r1=50.0,
        r2=50.0,
        discard_count=0,
    )

    assert upsilon_p.shape == (8, 8)
    assert upsilon_s.shape == (8, 8)
    assert np.all(np.isfinite(upsilon_p))
    assert np.all(np.isfinite(upsilon_s))


def test_generate_upsilon_matrices_is_deterministic_for_identical_inputs():
    first_p, first_s = generate_upsilon_matrices(
        height=4,
        width=5,
        x0=0.3,
        y0=0.2,
        r1=50.0,
        r2=50.0,
        discard_count=3,
    )
    second_p, second_s = generate_upsilon_matrices(
        height=4,
        width=5,
        x0=0.3,
        y0=0.2,
        r1=50.0,
        r2=50.0,
        discard_count=3,
    )

    np.testing.assert_array_equal(first_p, second_p)
    np.testing.assert_array_equal(first_s, second_s)


def test_generate_upsilon_matrices_rejects_invalid_dimensions():
    with pytest.raises(ValueError, match="height and width"):
        generate_upsilon_matrices(0, 8, 0.3, 0.2, 50.0, 50.0, 0)

    with pytest.raises(ValueError, match="height and width"):
        generate_upsilon_matrices(8, -1, 0.3, 0.2, 50.0, 50.0, 0)


def test_generate_upsilon_matrices_rejects_negative_discard_count():
    with pytest.raises(ValueError, match="discard_count"):
        generate_upsilon_matrices(8, 8, 0.3, 0.2, 50.0, 50.0, -1)
