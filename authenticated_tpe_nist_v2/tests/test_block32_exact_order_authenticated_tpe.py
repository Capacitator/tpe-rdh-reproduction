import hashlib
import sys
from pathlib import Path
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
REPO=ROOT.parent
sys.path.insert(0,str(REPO/'tpe_rdh_reproduction'/'src'))
import block32_exact_order_authenticated_tpe as exact
from pipeline import DemoPipelineParameters

KEY_TPE=bytes.fromhex("00112233445566778899aabbccddeeff102132435465768798a9babbdcedfe0f")
KEY_AUTH=hashlib.sha256(b"unit-test exact-order authentication key").digest()
IMAGE_ID=hashlib.sha256(b"unit-test exact-order ImageID").digest()[:16]
PAYLOAD=[(i*7+3)&1 for i in range(256)]


def _image():
    # Structured synthetic fixture with ample legacy RDH histogram capacity.
    # It is a regression input only, never part of the reported image corpus.
    y,x=np.indices((256,256))
    out=np.empty((256,256,3),dtype=np.uint8)
    for c in range(3):
        out[:,:,c]=(((x+3*y+5*c)%16)*16).astype(np.uint8)
    return out


def _encrypt():
    params=DemoPipelineParameters(block_size=32,key=KEY_TPE)
    enc=exact.encrypt_authenticated_tpe(_image(),PAYLOAD,params,KEY_AUTH,IMAGE_ID)
    return params,enc


def test_exact_order_roundtrip_and_authenticated_sidecar():
    params,enc=_encrypt()
    assert enc.group_count==48  # sixteen groups per channel
    assert enc.minimum_group_capacity>=256
    dec=exact.decrypt_authenticated_tpe(enc.marked_image,enc.layout_sidecar,params,
                                        KEY_AUTH,IMAGE_ID,enc.tpe_image_identifier,PAYLOAD)
    assert dec.accepted,dec.reason
    assert np.array_equal(dec.recovered_image,_image())
    assert dec.recovered_payload_bits==PAYLOAD


def test_tampered_image_is_rejected_before_plaintext_recovery():
    params,enc=_encrypt()
    tampered=enc.marked_image.copy()
    tampered[0,0,0]^=1
    dec=exact.decrypt_authenticated_tpe(tampered,enc.layout_sidecar,params,
                                        KEY_AUTH,IMAGE_ID,enc.tpe_image_identifier,PAYLOAD)
    assert not dec.accepted
    assert dec.recovered_image is None
    assert dec.failed_groups


def test_single_pixel_tamper_localizes_to_selected_four_block_group():
    _,enc=_encrypt()
    channel=1
    ids=exact.common._group_order(KEY_AUTH,channel,64)[0]
    block_id=ids[0]
    block_y,block_x=divmod(block_id,8)
    tampered=enc.marked_image.copy()
    tampered[block_y*32,block_x*32,channel]^=1
    result=exact.verify_tpe_ciphertext(tampered,enc.layout_sidecar,KEY_AUTH,IMAGE_ID)
    assert not result.accepted
    assert result.restored_tpe_ciphertext is None
    assert result.failed_groups==((channel,ids[0]),)


def test_tampered_layout_sidecar_is_rejected():
    params,enc=_encrypt()
    damaged=bytearray(enc.layout_sidecar)
    damaged[-1]^=1
    verified=exact.verify_tpe_ciphertext(enc.marked_image,bytes(damaged),KEY_AUTH,IMAGE_ID)
    assert not verified.accepted
    assert verified.restored_tpe_ciphertext is None


def test_wrong_image_id_is_rejected():
    _,enc=_encrypt()
    wrong=bytes([IMAGE_ID[0]^1])+IMAGE_ID[1:]
    verified=exact.verify_tpe_ciphertext(enc.marked_image,enc.layout_sidecar,KEY_AUTH,wrong)
    assert not verified.accepted
    assert verified.restored_tpe_ciphertext is None
