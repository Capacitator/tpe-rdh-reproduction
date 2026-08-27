from pathlib import Path
import sys

import numpy as np
import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from chaos import generate_upsilon_matrices
from substitution import (
    chaotic_pair_delta,
    decrypt_pair,
    encrypt_pair,
    index_to_pair,
    inverse_substitute_channel_blocks,
    pair_to_index,
    same_sum_pair_count,
    substitute_channel_blocks,
)


DEMO_VARTETHA = 10000.0


def test_same_sum_pair_count_matches_eq_9_boundaries():
    assert same_sum_pair_count(0) == 1
    assert same_sum_pair_count(1) == 2
    assert same_sum_pair_count(255) == 256
    assert same_sum_pair_count(256) == 255
    assert same_sum_pair_count(509) == 2
    assert same_sum_pair_count(510) == 1


@pytest.mark.parametrize(
    "pair",
    [(0, 0), (0, 255), (255, 0), (255, 255), (1, 254), (128, 127), (200, 55)],
)
def test_pair_to_index_and_index_to_pair_round_trip_boundary_values(pair):
    tau1, tau2 = pair
    s_tau = tau1 + tau2

    eta = pair_to_index(tau1, tau2)
    recovered = index_to_pair(eta, s_tau)

    assert recovered == pair


def test_chaotic_pair_delta_matches_eq_6():
    assert chaotic_pair_delta(0.2, 0.4, 10.0) == 6


@pytest.mark.parametrize(
    "pair",
    [(0, 0), (0, 255), (255, 0), (255, 255), (10, 20), (200, 55), (128, 129)],
)
def test_encrypted_pair_has_exactly_same_sum(pair):
    encrypted = encrypt_pair(pair[0], pair[1], 0.31, 0.27, DEMO_VARTETHA)

    assert sum(encrypted) == sum(pair)


@pytest.mark.parametrize(
    "pair",
    [(0, 0), (0, 255), (255, 0), (255, 255), (10, 20), (200, 55), (128, 129)],
)
def test_encrypt_then_decrypt_gives_exact_original_pair(pair):
    encrypted = encrypt_pair(pair[0], pair[1], 0.31, 0.27, DEMO_VARTETHA)
    decrypted = decrypt_pair(encrypted[0], encrypted[1], 0.31, 0.27, DEMO_VARTETHA)

    assert decrypted == pair


def test_random_pixel_pairs_encrypt_decrypt_and_stay_in_range():
    rng = np.random.default_rng(12345)

    for _ in range(1000):
        tau1 = int(rng.integers(0, 256))
        tau2 = int(rng.integers(0, 256))
        gamma1 = float(rng.random())
        gamma2 = float(rng.random())

        encrypted = encrypt_pair(tau1, tau2, gamma1, gamma2, DEMO_VARTETHA)
        decrypted = decrypt_pair(
            encrypted[0], encrypted[1], gamma1, gamma2, DEMO_VARTETHA
        )

        assert sum(encrypted) == tau1 + tau2
        assert 0 <= encrypted[0] <= 255
        assert 0 <= encrypted[1] <= 255
        assert decrypted == (tau1, tau2)


def test_channel_substitution_then_inverse_recovers_exact_original():
    channel = np.arange(64, dtype=np.uint8).reshape(8, 8)
    _, upsilon_s = generate_upsilon_matrices(8, 8, 0.3, 0.2, 50.0, 50.0, 0)

    encrypted = substitute_channel_blocks(channel, upsilon_s, 4, DEMO_VARTETHA)
    recovered = inverse_substitute_channel_blocks(encrypted, upsilon_s, 4, DEMO_VARTETHA)

    np.testing.assert_array_equal(recovered, channel)


def test_channel_substitution_preserves_pair_sums():
    channel = np.arange(64, dtype=np.uint8).reshape(8, 8)
    _, upsilon_s = generate_upsilon_matrices(8, 8, 0.3, 0.2, 50.0, 50.0, 0)

    encrypted = substitute_channel_blocks(channel, upsilon_s, 4, DEMO_VARTETHA)

    original_pairs = channel.reshape(2, 4, 2, 4).swapaxes(1, 2).reshape(-1, 16)
    encrypted_pairs = encrypted.reshape(2, 4, 2, 4).swapaxes(1, 2).reshape(-1, 16)
    for original_block, encrypted_block in zip(original_pairs, encrypted_pairs):
        for index in range(0, 16, 2):
            assert int(original_block[index]) + int(original_block[index + 1]) == int(
                encrypted_block[index]
            ) + int(encrypted_block[index + 1])


def test_channel_substitution_outputs_uint8_values_in_range():
    channel = np.arange(64, dtype=np.uint8).reshape(8, 8)
    _, upsilon_s = generate_upsilon_matrices(8, 8, 0.3, 0.2, 50.0, 50.0, 0)

    encrypted = substitute_channel_blocks(channel, upsilon_s, 4, DEMO_VARTETHA)

    assert encrypted.dtype == np.uint8
    assert encrypted.min() >= 0
    assert encrypted.max() <= 255


def test_negative_gamma_is_rejected_because_eq_6_uses_upsilon_s_prime():
    with pytest.raises(ValueError, match="non-negative"):
        chaotic_pair_delta(-0.1, 0.2, DEMO_VARTETHA)


def test_channel_substitution_uses_abs_for_negative_upsilon_s_values():
    channel = np.array([[40, 70], [120, 20]], dtype=np.uint8)
    upsilon_s = np.array([[-0.2, -0.4], [-0.31, -0.27]], dtype=np.float64)

    encrypted = substitute_channel_blocks(channel, upsilon_s, 2, DEMO_VARTETHA)

    expected_first_pair = encrypt_pair(40, 70, 0.2, 0.4, DEMO_VARTETHA)
    expected_second_pair = encrypt_pair(120, 20, 0.31, 0.27, DEMO_VARTETHA)
    expected = np.array(
        [
            [expected_first_pair[0], expected_first_pair[1]],
            [expected_second_pair[0], expected_second_pair[1]],
        ],
        dtype=np.uint8,
    )

    np.testing.assert_array_equal(encrypted, expected)
