"""Tests for the separate paper-specific RCM/HMAC prototype."""
from pathlib import Path
import hashlib
import hmac
from io import BytesIO
import sys

import numpy as np
import pytest
from PIL import Image

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import authenticated_tpe as a

KEY = bytes(range(32))
IMAGE_ID = bytes(range(16))


def test_key_derivation_known_answers():
    keys = a.derive_keys(KEY, 1)
    assert keys["Kch"].hex() == "97e1198fbd14ad6075f840f3b927f409470fee9e96a6fddb82d93ab0f1be1a47"
    assert keys["Ktpe"].hex() == "1fc6e601803dc259344165e87a674cf4a1751a47bf4704499c58d58206fb9b62"
    assert keys["Kr1"].hex() == "f346307d750a7949d18f29f9f4e22ad0b790296cc7e6fab0df093cab7086c272"
    assert keys["Kstruct"].hex() == "d80039f3d57379c89d54cf1e4c5182fb633ca2dbb506717f93bb5d508830e02b"
    auth = a.derive_keys(KEY)["Kauth"]
    assert auth.hex() == "147de1bc2bd0892d7aa55bbae4cb317ead56029b488ccbb885fd16d57b6a7017"
    assert a.derive_group_key(auth, IMAGE_ID, 1, [1, 2, 3, 4]).hex() == "e9fa70face6f7109b325e59efe381caacd067be215ac9b359c706c5ff6936cf1"
    assert a.derive_image_key(auth, IMAGE_ID).hex() == "e2d1110a18e0fa9518299ee537c7c41a54dbaa54c6d4e4045139ebe4ee177f2b"
    assert a.pair_shift(keys["Ktpe"], IMAGE_ID, 42, 511, 100) == 19
    assert a.block_r1(keys["Kr1"], 42) == 2
    assert a.derive_group_key(auth, IMAGE_ID, 1, [4, 3, 2, 1]) != a.derive_group_key(auth, IMAGE_ID, 1, [1, 2, 3, 4])


def test_key_derivation_independent_spec_recalculation():
    mac = lambda key, message: hmac.new(key, message, hashlib.sha256).digest()
    channel = 1
    kch = mac(KEY, b"channel" + bytes([channel]))
    assert a.derive_keys(KEY, channel)["Kch"] == kch
    assert a.derive_keys(KEY, channel)["Ktpe"] == mac(kch, b"tpe")
    assert a.derive_keys(KEY, channel)["Kr1"] == mac(kch, b"r1")
    assert a.derive_keys(KEY, channel)["Kstruct"] == mac(kch, b"struct")
    kauth = mac(KEY, b"auth")
    assert a.derive_keys(KEY)["Kauth"] == kauth
    group_message = IMAGE_ID + bytes([channel]) + b"".join(i.to_bytes(2, "big") for i in (1, 2, 3, 4))
    assert a.derive_group_key(kauth, IMAGE_ID, channel, (1, 2, 3, 4)) == mac(kauth, group_message)
    assert a.derive_image_key(kauth, IMAGE_ID) == mac(kauth, b"image" + IMAGE_ID)
    pair_msg = b"tpe-shift" + IMAGE_ID + (42).to_bytes(2, "big") + (511).to_bytes(2, "big")
    word = int.from_bytes(mac(a.derive_keys(KEY, channel)["Ktpe"], pair_msg)[:4], "big")
    assert a.pair_shift(a.derive_keys(KEY, channel)["Ktpe"], IMAGE_ID, 42, 511, 100) == word % 100
    r1_word = int.from_bytes(mac(a.derive_keys(KEY, channel)["Kr1"], b"r1" + (42).to_bytes(2, "big"))[:4], "big")
    assert a.block_r1(a.derive_keys(KEY, channel)["Kr1"], 42) == r1_word % 4


def test_drbg_and_paper_permutation_known_answer():
    rng = a.HMACDRBG(bytes(range(32)), b"", b"group-perm")
    assert [rng.generate4() for _ in range(4)] == [0x833513C6, 0xB64F37E2, 0x37299C7D, 0x7E60D678]
    flat = tuple(block for group in a.group_blocks(bytes(range(32)))[:2] for block in group)
    assert flat == (224, 3, 167, 218, 229, 171, 106, 172)

    # Independent compact reference implementation pins all 256 permutation values.
    key, value = bytes(32), bytes([1]) * 32

    def update(data):
        nonlocal key, value
        key = hmac.new(key, value + b"\x00" + data, "sha256").digest()
        value = hmac.new(key, value, "sha256").digest()
        if data:
            key = hmac.new(key, value + b"\x01" + data, "sha256").digest()
            value = hmac.new(key, value, "sha256").digest()

    def generate4():
        nonlocal value
        value = hmac.new(key, value, "sha256").digest()
        result = int.from_bytes(value[:4], "big")
        update(b"")
        return result

    update(bytes(range(32)) + b"group-perm")
    reference = list(range(256))
    for i in range(255, 0, -1):
        limit = ((1 << 32) // (i + 1)) * (i + 1)
        draw = generate4()
        while draw >= limit:
            draw = generate4()
        j = draw % (i + 1)
        reference[i], reference[j] = reference[j], reference[i]
    actual = tuple(b for group in a.group_blocks(bytes(range(32))) for b in group)
    assert actual == tuple(reference)
    assert hashlib.sha256(bytes(reference)).hexdigest() == "55f272be5c1686f05a22714dba3a2651d79cb11d14df3d66ba715d3e38ba8c38"


def test_grouping_is_a_partition_into_64_ordered_groups():
    for c in range(3):
        groups = a.group_blocks(a.derive_keys(KEY, c)["Kstruct"])
        assert len(groups) == 64
        assert all(len(g) == 4 and len(set(g)) == 4 for g in groups)
        assert sorted(b for g in groups for b in g) == list(range(256))


def test_image_ids_use_csprng_and_pair_shift_is_id_bound():
    ids = {a.generate_image_id() for _ in range(64)}
    assert len(ids) == 64
    assert all(len(x) == 16 for x in ids)
    ktpe = a.derive_keys(KEY, 0)["Ktpe"]
    shift = a.pair_shift(ktpe, IMAGE_ID, 7, 19, 101)
    assert shift == a.pair_shift(ktpe, IMAGE_ID, 7, 19, 101)  # Reuse repeats the stream; owners must not reuse IDs.
    assert shift != a.pair_shift(ktpe, bytes(reversed(IMAGE_ID)), 7, 19, 101)


def test_group_mac_binds_channel_image_content_and_order():
    carrier = np.zeros((512, 512, 3), dtype=np.uint8)
    ids = (3, 17, 29, 88)
    baseline = a._group_mac(carrier, KEY, IMAGE_ID, 0, ids)
    assert a._group_mac(carrier, KEY, IMAGE_ID, 1, ids) != baseline
    assert a._group_mac(carrier, KEY, bytes(reversed(IMAGE_ID)), 0, ids) != baseline
    assert a._group_mac(carrier, KEY, IMAGE_ID, 0, tuple(reversed(ids))) != baseline
    modified = carrier.copy(); a._get_block(modified, 0, ids[0])[0, 0] = 1
    assert a._group_mac(modified, KEY, IMAGE_ID, 0, ids) != baseline


def test_step1_roundtrip_and_pair_sum_on_random_vectors():
    rng = np.random.default_rng(7821)
    ktpe = a.derive_keys(KEY, 2)["Ktpe"]
    for i in range(2048):
        x, y = map(int, rng.integers(0, 256, size=2))
        x1, y1 = a.step1_pair(x, y, ktpe, IMAGE_ID, i % 256, i % 512)
        assert x + y == x1 + y1
        assert a.inverse_step1_pair(x1, y1, ktpe, IMAGE_ID, i % 256, i % 512) == (x, y)
        assert a._in_dc(x, y) == a._in_dc(x1, y1)


def test_step1_exhaustive_bijection_for_fixed_pair_parameters():
    ktpe = a.derive_keys(KEY, 1)["Ktpe"]
    outputs = set()
    for x in range(256):
        for y in range(256):
            encrypted = a.step1_pair(x, y, ktpe, IMAGE_ID, 19, 271)
            assert encrypted not in outputs
            outputs.add(encrypted)
            assert sum(encrypted) == x + y
            assert a.inverse_step1_pair(*encrypted, ktpe, IMAGE_ID, 19, 271) == (x, y)
    assert len(outputs) == 65536


def test_step2_exhaustive_bijection_for_each_r1():
    for r1 in range(4):
        outputs = set()
        for x in range(256):
            for y in range(256):
                encrypted = a.step2_pair(x, y, r1)
                assert encrypted not in outputs
                outputs.add(encrypted)
                assert a.inverse_step2_pair(*encrypted, r1) == (x, y)
        assert len(outputs) == 65536


def test_rcm_t_o_n_exhaustive_roundtrip_and_decoder_separation():
    for x in range(256):
        for y in range(256):
            kind = a.classify_pair(x, y)
            for bit in (0, 1):
                if kind == "T":
                    xp, yp = a.rcm_forward(x, y)
                    encoded = ((xp & ~1) | 1, (yp & ~1) | bit)
                    decoded = a.rcm_inverse(encoded[0] & ~1, encoded[1] & ~1)
                    assert decoded == (x, y)
                    assert 0 <= encoded[0] <= 255 and 0 <= encoded[1] <= 255
                elif kind == "O":
                    encoded = (x & ~1, (y & ~1) | bit)
                    assert (encoded[0] | 1, encoded[1] | 1) == (x, y)
                else:
                    encoded_x = x & ~1
                    assert not a._in_dc(encoded_x | 1, y | 1)
                    restored_x = encoded_x | (x & 1)
                    assert (restored_x, y) == (x, y)


def _pair_fixture_image() -> np.ndarray:
    image = np.zeros((512, 512, 3), dtype=np.uint8)
    patterns = ((100, 100), (101, 101), (0, 255))
    for c in range(3):
        for bid in range(4):
            block = np.empty((32, 32), dtype=np.uint8)
            pairs = np.asarray([patterns[(k + bid) % 3] for k in range(512)], dtype=np.uint8)
            block[:] = pairs.reshape(32, 32)
            a._get_block(image, c, bid)[:] = block
    return image


def test_rcm_embedding_extraction_restores_t_o_n_pairs_and_tag():
    image = _pair_fixture_image()
    before = image.copy()
    tag = bytes(range(32))
    slots = a._group_slots(0, (0, 1, 2, 3))
    ok, consumed, net = a.embed_group_tag(image, slots, tag)
    assert ok and consumed <= 2048 and net == 256
    extracted = a.extract_group_tag(image, slots)
    assert extracted is not None
    got, restored, consumed2 = extracted
    assert got == tag and consumed2 == consumed
    for bid in range(4):
        assert np.array_equal(a._get_block(restored, 0, bid), a._get_block(before, 0, bid))


def test_rcm_insufficient_capacity_does_not_partially_embed():
    image = np.zeros((512, 512, 3), dtype=np.uint8)
    pattern = np.tile(np.asarray([0, 255], dtype=np.uint8), (32, 16))
    for bid in range(4):
        a._get_block(image, 0, bid)[:] = pattern
    before = image.copy()
    ok, _, net = a.embed_group_tag(image, a._group_slots(0, (0, 1, 2, 3)), bytes(32))
    assert not ok and net < 256
    assert np.array_equal(image, before)


@pytest.fixture(scope="module")
def clean_group_case():
    image_path = PROJECT_ROOT.parent / "tpe_rdh_reproduction" / "input" / "uct_colour" / "airplane.tif"
    image = np.asarray(Image.open(image_path).convert("RGB").resize((512, 512)), dtype=np.uint8)
    result = a.protect_image(image, KEY, IMAGE_ID)
    return image, result


def test_group_mode_clean_authentication_exact_recovery(clean_group_case):
    original, protected = clean_group_case
    assert protected.mode == "group"
    assert protected.embedded_tags == 192
    verified = a.verify_and_decrypt(protected.marked_image, KEY, IMAGE_ID)
    assert verified.accepted and verified.mode == "group"
    assert len(verified.group_status) == 192
    assert all(status for _, _, status in verified.group_status)
    assert np.array_equal(verified.recovered_image, original)


def test_lossless_png_roundtrip_preserves_verification(clean_group_case):
    original, protected = clean_group_case
    stream = BytesIO()
    Image.fromarray(protected.marked_image, mode="RGB").save(stream, format="PNG")
    stream.seek(0)
    reloaded = np.asarray(Image.open(stream).convert("RGB"), dtype=np.uint8)
    verified = a.verify_and_decrypt(reloaded, KEY, IMAGE_ID)
    assert verified.accepted and np.array_equal(verified.recovered_image, original)


def test_modified_data_wrong_key_wrong_id_swaps_and_replacement_rejected(clean_group_case):
    original, protected = clean_group_case
    marked = protected.marked_image
    attacks = []
    one_bit = marked.copy(); one_bit[0, 0, 0] ^= 1; attacks.append((one_bit, KEY, IMAGE_ID))
    wrong_key = bytes([KEY[0] ^ 1]) + KEY[1:]; attacks.append((marked, wrong_key, IMAGE_ID))
    wrong_id = bytes([IMAGE_ID[0] ^ 1]) + IMAGE_ID[1:]; attacks.append((marked, KEY, wrong_id))
    swap = marked.copy()
    b0, b1 = a._get_block(swap, 0, 0).copy(), a._get_block(swap, 0, 1).copy()
    a._get_block(swap, 0, 0)[:] = b1; a._get_block(swap, 0, 1)[:] = b0
    attacks.append((swap, KEY, IMAGE_ID))
    cross = marked.copy()
    b0, b1 = a._get_block(cross, 0, 0).copy(), a._get_block(cross, 1, 0).copy()
    a._get_block(cross, 0, 0)[:] = b1; a._get_block(cross, 1, 0)[:] = b0
    attacks.append((cross, KEY, IMAGE_ID))
    replacement_image = original.copy()
    replacement_image[40:56, 80:96] = 255 - replacement_image[40:56, 80:96]
    replacement = a.protect_image(replacement_image, KEY, bytes(reversed(IMAGE_ID))).marked_image
    assert not np.array_equal(replacement, marked)
    attacks.append((replacement, KEY, IMAGE_ID))
    for attacked, key, image_id in attacks:
        verified = a.verify_and_decrypt(attacked, key, image_id)
        assert not verified.accepted
        assert verified.recovered_image is None
        assert verified.mode is None


def test_group_failure_localization_reports_group_and_never_partial_plaintext(clean_group_case):
    _, protected = clean_group_case
    attacked = protected.marked_image.copy()
    attacked[0, 0, 0] ^= 1
    verified = a.verify_and_decrypt(attacked, KEY, IMAGE_ID)
    assert not verified.accepted and verified.recovered_image is None
    assert verified.failed_groups
    assert all(c in (0, 1, 2) and 0 <= gi < 64 for c, gi in verified.failed_groups)


@pytest.fixture(scope="module")
def whole_image_case():
    # Four out-of-domain blocks in each channel force a group-capacity failure;
    # the remaining smooth blocks leave ample aggregate whole-image capacity.
    image = np.full((512, 512, 3), 100, dtype=np.uint8)
    out_domain = np.tile(np.asarray([0, 255], dtype=np.uint8), (32, 16))
    for c in range(3):
        ids = a.group_blocks(a.derive_keys(KEY, c)["Kstruct"])[0]
        for bid in ids:
            a._get_block(image, c, bid)[:] = out_domain
    return image, a.protect_image(image, KEY, IMAGE_ID)


def test_whole_image_fallback_clean_recovery_and_tamper_detection(whole_image_case):
    original, protected = whole_image_case
    assert protected.mode == "whole-image" and protected.embedded_tags == 1
    verified = a.verify_and_decrypt(protected.marked_image, KEY, IMAGE_ID)
    assert verified.accepted and verified.mode == "whole-image"
    assert np.array_equal(verified.recovered_image, original)
    attacked = protected.marked_image.copy(); attacked[0, 0, 0] ^= 1
    result = a.verify_and_decrypt(attacked, KEY, IMAGE_ID)
    assert not result.accepted and result.recovered_image is None


def test_entirely_unusable_image_is_rejected():
    image = np.tile(np.asarray([0, 255], dtype=np.uint8), (512, 256))[:, :, None]
    image = np.repeat(image, 3, axis=2)
    with pytest.raises(a.InsufficientCapacity):
        a.protect_image(image, KEY, IMAGE_ID)


def test_invalid_image_contract_and_bad_key_inputs_are_rejected():
    with pytest.raises(ValueError):
        a.protect_image(np.zeros((16, 16, 3), dtype=np.uint8), KEY, IMAGE_ID)
    with pytest.raises(ValueError):
        a.protect_image(np.zeros((512, 512, 3), dtype=np.uint8), b"short", IMAGE_ID)
    with pytest.raises(ValueError):
        a.protect_image(np.zeros((512, 512, 3), dtype=np.uint8), KEY, b"short")
