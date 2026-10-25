import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(REPO / "tpe_rdh_reproduction" / "src"))

import block32_exact_order_authenticated_tpe as exact
import four_pixel_pipeline as fourpx
from four_pixel_spe import decrypt4, encrypt4
import four_pixel_pipeline

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


def test_paper_sum_case_boundaries_and_case2_inverse_sign():
    # Exercise both sides of every appendix boundary and every case. The
    # paper's prose differs at S=255; its appendix inequalities put S=255 in
    # Case 2 when e=255, and this implementation follows those equations.
    for total in (0, 254, 255, 256, 510, 511, 765, 766, 1020):
        source=[]
        rest=total
        for _ in range(4):
            value=min(rest,255)
            source.append(value)
            rest-=value
        assert rest==0
        for key in (0,1,127,255):
            cipher=encrypt4(source,key)
            assert sum(cipher)==total
            assert decrypt4(cipher,key)==tuple(source)
    # Case 2 high-sum c branch: its inverse is e - ((e-c'-r) mod M).
    source=(0,0,255,1)  # S=256; S-S1=256 selects the high branch.
    for key in (0,1,17,127,255):
        encrypted=encrypt4(source,key)
        assert decrypt4(encrypted,key)==source
    key=1
    case2_cipher=encrypt4(source,key)
    rem=sum(source)-source[0]-source[1]
    wrong_c=255-((255-case2_cipher[2]+key)%(2*255-rem+1))
    assert wrong_c!=source[2]  # The appendix's printed +r does not invert Case 2.


def test_four_pixel_key_quantization_covers_full_byte_domain():
    matrix=np.zeros((32,32),dtype=np.float64)
    matrix.reshape(-1)[::4][:5]=[-1.0,-0.5,0.0,0.5,1.0]
    keys=four_pixel_pipeline._keys_from_matrix(matrix,0,0)
    assert keys[:5].tolist()==[1,64,128,192,255]


def test_four_pixel_pipeline_rejects_omitted_default_key():
    params = fourpx.DemoPipelineParameters()
    with pytest.raises(ValueError, match="key is required"):
        fourpx._generate_channel_matrices(32, 32, params, IMAGE_ID)


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


@pytest.fixture(scope="module")
def serialized_bundle(tmp_path_factory):
    image=_image()
    params=fourpx.DemoPipelineParameters(block_size=32,key=KEY_TPE)
    encrypted=exact.encrypt_authenticated_tpe(image,PAYLOAD,params,KEY_AUTH,
                                                IMAGE_ID,tpe_module=fourpx)
    folder=tmp_path_factory.mktemp("fourpx-bundle")
    png=folder/"ciphertext.png"
    sidecar=folder/"ciphertext.atpe"
    Image.fromarray(encrypted.marked_image).save(png)
    sidecar.write_bytes(encrypted.layout_sidecar)
    return image,encrypted,png,sidecar


def test_versioned_saved_bundle_recovers_without_in_memory_result(serialized_bundle):
    image,encrypted,png,sidecar=serialized_bundle
    header=exact._SIDECAR_HEADER.unpack(encrypted.layout_sidecar[:exact._SIDECAR_HEADER.size])
    assert header[:6]==(b"ATPE",1,0,0,256,256)
    assert header[6]==IMAGE_ID
    saved=np.asarray(Image.open(png).convert("RGB"),dtype=np.uint8)
    recovered=exact.decrypt_authenticated_tpe_bundle(saved,sidecar.read_bytes(),KEY_TPE,
                                                       KEY_AUTH,tpe_module=fourpx)
    assert recovered.accepted,recovered.reason
    assert np.array_equal(recovered.recovered_image,image)
    assert recovered.recovered_payload_bits==PAYLOAD

    script=ROOT/"scripts"/"recover_four_pixel_bundle.py"
    child=subprocess.run([sys.executable,str(script),str(png),str(sidecar)],
        env={**os.environ,"FOURPX_TPE_KEY_HEX":KEY_TPE.hex(),
             "FOURPX_AUTH_KEY_HEX":KEY_AUTH.hex()},capture_output=True,text=True,check=True)
    child_result=json.loads(child.stdout)
    assert child_result["accepted"] is True
    assert child_result["payload_bits"]==PAYLOAD
    assert child_result["recovered_image_sha256"]==hashlib.sha256(image.tobytes()).hexdigest()


def test_versioned_header_is_aead_authenticated(serialized_bundle):
    image,encrypted,_,_=serialized_bundle
    for offset in (4,8,12,16,28):  # version, height, width, image ID and nonce/header
        tampered=bytearray(encrypted.layout_sidecar)
        tampered[offset]^=1
        result=exact.decrypt_authenticated_tpe_bundle(encrypted.marked_image,
            bytes(tampered),KEY_TPE,KEY_AUTH,tpe_module=fourpx)
        assert not result.accepted and result.recovered_image is None


def test_wrong_keys_ids_and_malformed_or_replaced_sidecars_fail_closed(serialized_bundle):
    image,encrypted,png,sidecar=serialized_bundle
    marked=np.asarray(Image.open(png).convert("RGB"),dtype=np.uint8)
    cases=[
        (encrypted.layout_sidecar,KEY_TPE,bytes([KEY_AUTH[0]^1])+KEY_AUTH[1:],None),
        (encrypted.layout_sidecar,bytes([KEY_TPE[0]^1])+KEY_TPE[1:],KEY_AUTH,None),
        (encrypted.layout_sidecar,KEY_TPE,KEY_AUTH,b"wrong-image-id!!"),
        (encrypted.layout_sidecar[:-9],KEY_TPE,KEY_AUTH,None),
        (encrypted.layout_sidecar[:20],KEY_TPE,KEY_AUTH,None),
    ]
    changed=bytearray(encrypted.layout_sidecar); changed[-1]^=1
    cases.append((bytes(changed),KEY_TPE,KEY_AUTH,None))
    donor_id=hashlib.sha256(b"replacement sidecar donor").digest()[:16]
    donor=exact.encrypt_authenticated_tpe(np.roll(image,1,axis=1).copy(),PAYLOAD,
        fourpx.DemoPipelineParameters(block_size=32,key=KEY_TPE),KEY_AUTH,donor_id,tpe_module=fourpx)
    cases.append((donor.layout_sidecar,KEY_TPE,KEY_AUTH,None))
    for blob,tpe_key,auth_key,image_id in cases:
        result=exact.decrypt_authenticated_tpe(marked,blob,
            fourpx.DemoPipelineParameters(block_size=32,key=tpe_key),auth_key,
            image_id,None,None,tpe_module=fourpx)
        assert not result.accepted
        assert result.recovered_image is None


def test_tamper_localizes_across_channels_and_block_locations(serialized_bundle):
    _,encrypted,_,_=serialized_bundle
    for channel,block_id in ((0,0),(1,19),(2,63)):
        ids=next(g for g in exact.common._group_order(KEY_AUTH,channel,64) if block_id in g)
        by,bx=divmod(block_id,8)
        tampered=encrypted.marked_image.copy()
        tampered[by*32+3,bx*32+7,channel]^=1
        result=exact.decrypt_authenticated_tpe(tampered,encrypted.layout_sidecar,
            fourpx.DemoPipelineParameters(block_size=32,key=KEY_TPE),KEY_AUTH,
            None,None,None,tpe_module=fourpx)
        assert not result.accepted and result.recovered_image is None
        assert result.failed_groups==((channel,ids[0]),)

    # Two modified blocks in one authentication group still identify that one
    # group; two separate groups identify both affected groups.
    channel=2
    groups=exact.common._group_order(KEY_AUTH,channel,64)
    same_group=groups[3]
    tampered=encrypted.marked_image.copy()
    for block_id in same_group[:2]:
        by,bx=divmod(block_id,8)
        tampered[by*32,bx*32,channel]^=1
    result=exact.verify_tpe_ciphertext(tampered,encrypted.layout_sidecar,KEY_AUTH,None)
    assert not result.accepted and result.restored_tpe_ciphertext is None
    assert result.failed_groups==((channel,same_group[0]),)

    second_group=groups[12]
    by,bx=divmod(second_group[0],8)
    tampered[by*32+1,bx*32+1,channel]^=1
    result=exact.verify_tpe_ciphertext(tampered,encrypted.layout_sidecar,KEY_AUTH,None)
    assert not result.accepted and result.restored_tpe_ciphertext is None
    assert set(result.failed_groups)=={(channel,same_group[0]),(channel,second_group[0])}
