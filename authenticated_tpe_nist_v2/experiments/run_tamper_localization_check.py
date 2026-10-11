#!/usr/bin/env python3
"""Tamper/localization checks against the saved real-image output artifact."""
from __future__ import annotations
import csv,hashlib,sys
from pathlib import Path
import numpy as np
from PIL import Image
ROOT=Path(__file__).resolve().parents[1]
WORK=ROOT.parent
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(WORK/'tpe_rdh_reproduction'/'src'))
import block32_exact_order_authenticated_tpe as exact
import block32_authenticated_tpe as common
OUT=ROOT/'output'/'metrics'/'flowchart_exact_order_compensated'
AUTH_KEY=hashlib.sha256(b'public reproducible research authentication key fixture').digest()


def main():
    name='couple'
    row=next(r for r in csv.DictReader((OUT/'metrics.csv').open(encoding='utf-8')) if r['image']==name)
    image_id=bytes.fromhex(row['image_id_hex'])
    image=np.asarray(Image.open(OUT/row['authenticated_png']).convert('RGB'),dtype=np.uint8)
    sidecar=(OUT/row['layout_sidecar']).read_bytes()
    clean=exact.verify_tpe_ciphertext(image,sidecar,AUTH_KEY,image_id)
    if not clean.accepted:raise AssertionError('saved unmodified output did not verify')

    channel=1;nblocks=(int(row['height'])//32)*(int(row['width'])//32)
    ids=common._group_order(AUTH_KEY,channel,nblocks)[0]
    block_id=ids[0];blocks_x=int(row['width'])//32
    by,bx=divmod(block_id,blocks_x)
    changed=image.copy();changed[by*32,bx*32,channel]^=1
    pixel=exact.verify_tpe_ciphertext(changed,sidecar,AUTH_KEY,image_id)
    expected=((channel,int(ids[0])),)
    if pixel.accepted or pixel.failed_groups!=expected:
        raise AssertionError(f'pixel tamper was not localized to {expected}: {pixel.failed_groups}')

    damaged=bytearray(sidecar);damaged[-1]^=1
    side=exact.verify_tpe_ciphertext(image,bytes(damaged),AUTH_KEY,image_id)
    if side.accepted:raise AssertionError('tampered sidecar was accepted')
    wrong_iid=bytes([image_id[0]^1])+image_id[1:]
    iid=exact.verify_tpe_ciphertext(image,sidecar,AUTH_KEY,wrong_iid)
    if iid.accepted:raise AssertionError('wrong ImageID was accepted')

    rows=[
        {'case':'untampered saved couple output','accepted':clean.accepted,'failed_groups':str(clean.failed_groups),'expected_group':'','reason':clean.reason},
        {'case':'one pixel flipped in selected group','accepted':pixel.accepted,'failed_groups':str(pixel.failed_groups),'expected_group':str(expected),'reason':pixel.reason},
        {'case':'one sidecar authentication bit flipped','accepted':side.accepted,'failed_groups':str(side.failed_groups),'expected_group':'','reason':side.reason},
        {'case':'wrong ImageID','accepted':iid.accepted,'failed_groups':str(iid.failed_groups),'expected_group':'','reason':iid.reason},
    ]
    path=OUT/'tamper_checks.csv'
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)
    print(f'Wrote {path}; selected expected/detected group={expected}/{pixel.failed_groups}')

if __name__=='__main__':main()
