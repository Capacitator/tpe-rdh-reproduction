from __future__ import annotations
import sys
from pathlib import Path
import numpy as np
from PIL import Image

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
REPO=ROOT.parent
sys.path.insert(0,str(REPO/'tpe_rdh_reproduction'/'src'))
import block32_authenticated_tpe as hybrid
from pipeline import DemoPipelineParameters
from rdh import bits_from_bytes

TPE_KEY=bytes.fromhex('00112233445566778899aabbccddeeff102132435465768798a9babbdcedfe0f')
AUTH_KEY=bytes.fromhex('a1'*32)
PAYLOAD=bits_from_bytes(b'0123456789ABCDEF0123456789ABCDEF')
IID=bytes.fromhex('00112233445566778899aabbccddeeff')


def sample(h=256,w=256):
    if (h,w)==(256,256):
        path=ROOT.parent/'tpe_rdh_reproduction'/'input'/'uct_colour'/'couple.tif'
        with Image.open(path) as im: return np.asarray(im.convert('RGB'),dtype=np.uint8)
    rng=np.random.default_rng(123)
    return rng.integers(0,256,size=(h,w,3),dtype=np.uint8)


def test_group_auth_roundtrip_on_tpe_ciphertext():
    image=sample()
    params=DemoPipelineParameters(block_size=32,key=TPE_KEY)
    combined=hybrid.encrypt_authenticated_tpe(image,PAYLOAD,params,AUTH_KEY,IID)
    dec=hybrid.decrypt_authenticated_tpe(combined.marked_image,PAYLOAD,params,AUTH_KEY,IID,combined.tpe_image_identifier)
    assert dec.accepted
    assert dec.recovered_payload_bits==PAYLOAD
    assert np.array_equal(dec.recovered_image,image)


def test_group_tamper_withholds_plaintext():
    image=sample()
    params=DemoPipelineParameters(block_size=32,key=TPE_KEY)
    combined=hybrid.encrypt_authenticated_tpe(image,PAYLOAD,params,AUTH_KEY,IID)
    modified=combined.marked_image.copy();modified[70,90,1]^=1
    dec=hybrid.decrypt_authenticated_tpe(modified,PAYLOAD,params,AUTH_KEY,IID,combined.tpe_image_identifier)
    assert not dec.accepted
    assert dec.recovered_image is None
    assert dec.failed_groups


def test_authentication_id_changes_result_and_wrong_id_fails():
    image=sample()
    params=DemoPipelineParameters(block_size=32,key=TPE_KEY)
    combined=hybrid.encrypt_authenticated_tpe(image,PAYLOAD,params,AUTH_KEY,IID)
    wrong=bytes.fromhex('ff'*16)
    assert not hybrid.verify_tpe_ciphertext(combined.marked_image,AUTH_KEY,wrong).accepted


def test_rejects_dimensions_not_supported_by_block_grouping():
    with __import__('pytest').raises(ValueError): hybrid._dimensions(sample(250,256))
