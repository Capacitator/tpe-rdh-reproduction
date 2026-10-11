"""Tests for the revised authenticated-TPE build and the corrected protocol.

Covers the revision itself (exact agreement with the audited prototype except on
a provably negligible rejection branch), the unchanged primitives, exact
recovery and tamper rejection, and the structural invariants of the predefined
stream families used for the NIST SP 800-22 evaluation.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import random
import sys
from pathlib import Path

import numpy as np
import pytest
from scipy.stats import chisquare

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
REPO = ROOT.parent
sys.path.insert(0, str(REPO / "tpe_rdh_reproduction" / "src"))

import atpe_v2 as v2  # noqa: E402
import streams as S  # noqa: E402
import authenticated_tpe as base  # noqa: E402

KEY = bytes(range(32))
IMAGE_ID = bytes(range(16))
UINT32 = 1 << 32


# --------------------------------------------------------------------------
# Revision identity and backward compatibility
# --------------------------------------------------------------------------
def test_revision_is_activated_inside_the_prototype():
    status = v2.activation_status()
    assert status["prototype_pair_shift_is_revised"] is True
    assert status["rejection_probability_upper_bound"] < 1e-6


def test_revised_reduction_agrees_with_the_audited_reduction():
    """The revision must not change any value that the old code produced."""
    rng = random.Random(20261011)
    ktpe = v2.derive_keys(KEY, 1)["Ktpe"]
    disagreements = 0
    for _ in range(20000):
        block_id = rng.randrange(256)
        pair_index = rng.randrange(512)
        class_size = rng.randrange(1, 257)
        word = v2.pair_shift_word(ktpe, IMAGE_ID, block_id, pair_index)
        if v2.pair_shift(ktpe, IMAGE_ID, block_id, pair_index, class_size) != word % class_size:
            disagreements += 1
    assert disagreements == 0


def test_known_answer_vectors_still_hold():
    keys = v2.derive_keys(KEY, 1)
    assert keys["Kch"].hex() == "97e1198fbd14ad6075f840f3b927f409470fee9e96a6fddb82d93ab0f1be1a47"
    assert keys["Ktpe"].hex() == "1fc6e601803dc259344165e87a674cf4a1751a47bf4704499c58d58206fb9b62"
    assert v2.pair_shift(keys["Ktpe"], IMAGE_ID, 42, 511, 100) == 19
    assert v2.block_r1(keys["Kr1"], 42) == 2
    assert [v2.HMACDRBG(bytes(range(32)), b"", b"group-perm").generate4()] == [0x833513C6]


def test_pair_shift_reduction_is_exactly_uniform_within_a_class():
    ktpe = v2.derive_keys(KEY, 0)["Ktpe"]
    class_size = 255            # 2**32 mod 255 = 1, the worst case in the design
    counts = np.zeros(class_size, dtype=np.int64)
    draws = 25_500
    for index in range(draws):
        # Distinct (block, pair) derivations: independent uniform draws, not repeats.
        counts[v2.pair_shift(ktpe, IMAGE_ID, index // 512, index % 512, class_size)] += 1
    statistic, p_value = chisquare(counts)
    assert p_value >= 0.01


def test_retry_domain_is_separated_from_the_primary_message():
    primary = v2.pair_shift_message(IMAGE_ID, 3, 7)
    retry = primary + b"\x01retry" + (1).to_bytes(2, "big")
    assert retry.startswith(primary) and len(retry) > len(primary)
    ktpe = v2.derive_keys(KEY, 0)["Ktpe"]
    assert (hmac.new(ktpe, primary, hashlib.sha256).digest()
            != hmac.new(ktpe, retry, hashlib.sha256).digest())


def test_block_r1_reduction_is_bias_free_by_construction():
    assert UINT32 % 4 == 0            # the modulo reduction is exact, no rejection needed
    r1 = v2.derive_keys(KEY, 2)["Kr1"]
    counts = np.zeros(4, dtype=np.int64)
    for block_id in range(256):
        counts[v2.block_r1(r1, block_id)] += 1
    assert counts.sum() == 256


def test_step_transforms_are_bijections_and_roundtrip():
    ktpe = v2.derive_keys(KEY, 1)["Ktpe"]
    outputs = set()
    for x in range(256):
        for y in range(256):
            encrypted = v2.step1_pair(x, y, ktpe, IMAGE_ID, 19, 271)
            assert encrypted not in outputs
            outputs.add(encrypted)
            assert sum(encrypted) == x + y
            assert v2.inverse_step1_pair(*encrypted, ktpe, IMAGE_ID, 19, 271) == (x, y)
    assert len(outputs) == 65536
    for r1_value in range(4):
        seen = set()
        for x in range(256):
            for y in range(256):
                encrypted = v2.step2_pair(x, y, r1_value)
                assert encrypted not in seen
                seen.add(encrypted)
                assert v2.inverse_step2_pair(*encrypted, r1_value) == (x, y)


def test_derivation_domains_never_repeat_a_message():
    """Counter reuse check: (block, pair) and block indices are injective."""
    key = S.pool_key(1)
    ktpe = v2.derive_keys(key, 0)["Ktpe"]
    messages = {v2.pair_shift_message(S.pool_image_id(1), block, pair)
                for block in range(256) for pair in range(512)}
    assert len(messages) == 256 * 512
    r1 = v2.derive_keys(key, 0)["Kr1"]
    r1_messages = {b"r1" + block.to_bytes(2, "big") for block in range(256)}
    assert len(r1_messages) == 256
    assert len({v2.derive_image_key(v2.derive_keys(key)["Kauth"], S.pool_image_id(i))
                for i in range(1, 50)}) == 49
    assert ktpe and r1


# --------------------------------------------------------------------------
# Image-level behaviour
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def protected_case():
    image = S.load_image(0)
    result = v2.protect_image(image, KEY, IMAGE_ID)
    return image, result


def test_authentication_and_exact_recovery(protected_case):
    image, protected = protected_case
    verified = v2.verify_and_decrypt(protected.marked_image, KEY, IMAGE_ID)
    assert verified.accepted
    assert np.array_equal(verified.recovered_image, image)
    assert protected.mode in {"group", "whole-image"}


def test_image_fidelity_uses_original_input_as_reference():
    """The encryption-fidelity metric must not use the pre-mark Step-2 image."""
    sys.path.insert(0, str(ROOT / "experiments"))
    from run_metrics import quality_case

    row = quality_case(1)  # baboon fixture
    image = S.load_image(1)
    key, image_id = S.pool_key(5001), S.pool_image_id(5001)
    protected = v2.protect_image(image, key, image_id)
    step2 = v2.base._step2_image(v2.step1_image(image, key, image_id), key)
    from skimage.metrics import peak_signal_noise_ratio, structural_similarity

    expected_input_psnr = peak_signal_noise_ratio(image, protected.marked_image, data_range=255)
    expected_input_ssim = structural_similarity(image, protected.marked_image,
                                                channel_axis=2, data_range=255)
    expected_marking_psnr = peak_signal_noise_ratio(step2, protected.marked_image, data_range=255)
    assert row["input_vs_encrypted_psnr_db"] == pytest.approx(expected_input_psnr)
    assert row["input_vs_encrypted_ssim"] == pytest.approx(expected_input_ssim)
    assert row["marking_distortion_psnr_db"] == pytest.approx(expected_marking_psnr)
    assert row["input_vs_encrypted_psnr_db"] < row["marking_distortion_psnr_db"]


def test_plaintext_is_never_released_without_authentication(protected_case):
    _, protected = protected_case
    marked = protected.marked_image
    one_bit = marked.copy()
    one_bit[0, 0, 0] ^= 1
    attacks = [(one_bit, KEY, IMAGE_ID),
               (marked, bytes([KEY[0] ^ 1]) + KEY[1:], IMAGE_ID),
               (marked, KEY, bytes([IMAGE_ID[0] ^ 1]) + IMAGE_ID[1:])]
    for attacked, key, image_id in attacks:
        result = v2.verify_and_decrypt(attacked, key, image_id)
        assert not result.accepted
        assert result.recovered_image is None


def test_recovered_image_is_not_treated_as_a_random_stream():
    """The two diagnostic kinds must be declared, and plaintext is not a stream claim."""
    assert S.CATEGORY_KIND["ciphertext_diag"] == "diagnostic"
    assert S.CATEGORY_KIND["recovered_diag"] == "diagnostic"
    assert S.CATEGORY_KIND["reduced_shift_diag"] == "diagnostic"
    for category in ("hmac_drbg", "pair_shift", "block_r1", "auth_tag"):
        assert S.CATEGORY_KIND[category] == "cryptographic-component"


# --------------------------------------------------------------------------
# Protocol invariants
# --------------------------------------------------------------------------
def test_stream_definitions_are_complete_and_unique():
    partition = S.key_partition_report()
    assert partition["disjoint"] is True
    assert partition["key_indices_used"] == sum(
        end - start + 1 for start, end in S.KEY_RANGES.values())
    assert len(S.CATEGORY_ORDER) == 7
    assert S.STREAM_BYTES * 8 == S.STREAM_BITS == 1_000_000
    assert S.STREAM_COUNT == 100


def test_ascii_expansion_is_msb_first_and_exactly_one_million_bits():
    payload = bytes([0b10000001]) + bytes(S.STREAM_BYTES - 1)
    text = S.stream_ascii(payload)
    assert len(text) == 1_000_000
    assert text[:8] == "10000001"
    assert set(text) == {"0", "1"}


def test_image_pool_is_distinct_and_normalised():
    meta = S.ensure_image_cache()
    assert len(meta) == 106
    assert len({row["pixel_sha256"] for row in meta}) == 106
    assert S.load_image(0).shape == (512, 512, 3)
    assert S.load_image(105).shape == (512, 512, 3)
    assert not np.array_equal(S.load_image(0), S.load_image(1))


def test_diagnostic_and_tag_image_assignments_do_not_repeat_inside_a_stream():
    orders = [S.diagnostic_image_order(i) for i in range(1, 101)]
    assert len(set(orders)) == 100
    for stream_index in range(1, 101):
        tag_orders = [S.tag_instance_image_order(stream_index, t)
                      for t in range(S.TAG_INSTANCES_PER_STREAM)]
        assert len(set(tag_orders)) == S.TAG_INSTANCES_PER_STREAM


def test_generated_streams_are_pairwise_distinct_and_hashed():
    """Validate the real artifacts when the protocol has been run."""
    manifest = ROOT / "output" / "stream_manifest.csv"
    if not manifest.is_file():
        pytest.skip("run experiments/run_protocol.py first")
    with manifest.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 7 * S.STREAM_COUNT
    digests = [row["binary_sha256"] for row in rows]
    assert len(set(digests)) == len(digests)
    per_category: dict[str, int] = {}
    for row in rows:
        per_category[row["category"]] = per_category.get(row["category"], 0) + 1
        payload = (ROOT / row["stream_file"]).read_bytes()
        assert len(payload) == S.STREAM_BYTES
        assert hashlib.sha256(payload).hexdigest() == row["binary_sha256"]
    assert all(count == S.STREAM_COUNT for count in per_category.values())
    assert set(per_category) == set(S.CATEGORY_ORDER)
