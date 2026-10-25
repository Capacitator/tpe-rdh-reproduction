import hashlib
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(REPO / "tpe_rdh_reproduction" / "src"))

import block32_exact_order_authenticated_tpe as exact
import four_pixel_pipeline as fourpx
from four_pixel_spe import decrypt4, encrypt4

KEY_TPE = bytes.fromhex("00112233445566778899aabbccddeeff102132435465768798a9babbdcedfe0f")
KEY_AUTH = hashlib.sha256(b"unit-test four-pixel authentication key").digest()
IMAGE_ID = hashlib.sha256(b"unit-test four-pixel ImageID").digest()[:16]
PAYLOAD = [(i * 11 + 5) & 1 for i in range(128)]


def _image():
    y, x = np.indices((256, 256))
    out = np.empty((256, 256, 3), dtype=np.uint8)
    for c in range(3):
        out[:, :, c] = (((x + 3 * y + 5 * c) % 16) * 16).astype(np.uint8)
    return out


def test_four_pixel_transform_exactly_inverts_and_preserves_sum():
    rng = np.random.default_rng(481516)
    values = rng.integers(0, 256, size=(20000, 4), dtype=np.uint16)
    keys = rng.integers(0, 256, size=len(values), dtype=np.uint16)
    # Deliberately include all four sum intervals, zero-key and maximal-key edges.
    for src, key in zip(values, keys):
        original = tuple(map(int, src))
        r = int(key)
        cipher = encrypt4(original, r)
        assert sum(cipher) == sum(original)
        assert decrypt4(cipher, r) == original
    for src, key in [((0, 0, 0, 0), 0), ((255, 255, 255, 255), 255),
                     ((255, 0, 0, 0), 1), ((0, 255, 255, 0), 255)]:
        assert decrypt4(encrypt4(src, key), key) == src


def test_four_pixel_pipeline_exact_recovery_and_sum_preserving_substitution():
    image = _image()
    params = fourpx.DemoPipelineParameters(block_size=32, key=KEY_TPE)
    enc = fourpx.encrypt_rgb_image(image, PAYLOAD, params)
    assert np.array_equal(fourpx.decrypt_rgb_image(enc, params).recovered_image, image)
    dec = fourpx.decrypt_rgb_image(enc, params)
    rdh_sums = enc.marked_image.reshape(8, 32, 8, 32, 3).sum(axis=(1, 3), dtype=np.uint64)
    cipher_sums = enc.encrypted_image.reshape(8, 32, 8, 32, 3).sum(axis=(1, 3), dtype=np.uint64)
    # The native RDH tag stage can change thumbnail sums; the outer authenticated
    # wrapper restores source sums reversibly before releasing the ciphertext.
    assert not np.array_equal(rdh_sums, image.reshape(8, 32, 8, 32, 3).sum(axis=(1, 3), dtype=np.uint64))
    assert np.array_equal(cipher_sums, rdh_sums)


def _authenticated():
    params = fourpx.DemoPipelineParameters(block_size=32, key=KEY_TPE)
    enc = exact.encrypt_authenticated_tpe(
        _image(), PAYLOAD, params, KEY_AUTH, IMAGE_ID, tpe_module=fourpx
    )
    return params, enc


def test_four_pixel_native_rdh_carries_tags_and_user_payload():
    image = _image()
    params = fourpx.DemoPipelineParameters(block_size=32, key=KEY_TPE)
    enc = fourpx.encrypt_rgb_image(image, PAYLOAD, params)
    assert len(enc.rdh_infos) == 3
    assert [info.payload_length for info in enc.rdh_infos] == [256 + len(PAYLOAD), 256, 256]
    assert np.array_equal(fourpx.decrypt_rgb_image(enc, params).recovered_image, image)
    tampered = enc.encrypted_image.copy()
    tampered[13, 27, 0] ^= 1
    try:
        fourpx.decrypt_rgb_image(tampered, fourpx.DemoPipelineParameters(block_size=32, key=KEY_TPE, image_identifier=enc.image_identifier), payload_bits=PAYLOAD)
    except ValueError:
        pass
    else:
        raise AssertionError("four-pixel RDH tag accepted a modified ciphertext")


def test_four_pixel_authentication_exact_recovery():
    params, enc = _authenticated()
    dec = exact.decrypt_authenticated_tpe(
        enc.marked_image, enc.layout_sidecar, params, KEY_AUTH, IMAGE_ID,
        None, PAYLOAD, tpe_module=fourpx
    )
    assert dec.accepted, dec.reason
    assert np.array_equal(dec.recovered_image, _image())
    assert dec.recovered_payload_bits == PAYLOAD
    verified = exact.verify_tpe_ciphertext(enc.marked_image, enc.layout_sidecar, KEY_AUTH, IMAGE_ID)
    assert verified.tpe_image_identifier == enc.tpe_image_identifier
    assert enc.group_count == 48
    source_sums = _image().reshape(8, 32, 8, 32, 3).sum(axis=(1, 3), dtype=np.uint64)
    cipher_sums = enc.marked_image.reshape(8, 32, 8, 32, 3).sum(axis=(1, 3), dtype=np.uint64)
    assert np.array_equal(source_sums, cipher_sums)


def test_four_pixel_authentication_detects_and_localizes_one_pixel_tamper():
    _, enc = _authenticated()
    channel = 1
    ids = exact.common._group_order(KEY_AUTH, channel, 64)[0]
    block_y, block_x = divmod(ids[0], 8)
    tampered = enc.marked_image.copy()
    tampered[block_y * 32 + 7, block_x * 32 + 9, channel] ^= 1
    result = exact.verify_tpe_ciphertext(tampered, enc.layout_sidecar, KEY_AUTH, IMAGE_ID)
    assert not result.accepted
    assert result.restored_tpe_ciphertext is None
    assert result.failed_groups == ((channel, ids[0]),)


def test_cross_image_rgb_block_splice_is_detected_in_each_channel_group():
    image = _image()
    donor = np.roll(image, shift=1, axis=1).copy()
    params = fourpx.DemoPipelineParameters(block_size=32, key=KEY_TPE)
    donor_id = hashlib.sha256(b"donor image id").digest()[:16]
    target_id = hashlib.sha256(b"target image id").digest()[:16]
    donor_enc = exact.encrypt_authenticated_tpe(
        donor, PAYLOAD, params, KEY_AUTH, donor_id, tpe_module=fourpx
    )
    target_enc = exact.encrypt_authenticated_tpe(
        image, PAYLOAD, params, KEY_AUTH, target_id, tpe_module=fourpx
    )
    block_id = 5
    by, bx = divmod(block_id, 8)
    splice = target_enc.marked_image.copy()
    y0, x0 = by * 32, bx * 32
    splice[y0:y0 + 32, x0:x0 + 32, :] = donor_enc.marked_image[y0:y0 + 32, x0:x0 + 32, :]
    result = exact.verify_tpe_ciphertext(splice, target_enc.layout_sidecar, KEY_AUTH, target_id)
    expected = tuple(sorted(
        (c, next(g[0] for g in exact.common._group_order(KEY_AUTH, c, 64) if block_id in g))
        for c in range(3)
    ))
    assert not result.accepted
    assert result.restored_tpe_ciphertext is None
    assert tuple(sorted(result.failed_groups)) == expected
