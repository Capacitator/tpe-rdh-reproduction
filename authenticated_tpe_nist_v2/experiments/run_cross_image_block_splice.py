#!/usr/bin/env python3
"""Test both cross-image block-splice directions on saved authenticated PNGs."""
from __future__ import annotations
import csv, hashlib, sys
from pathlib import Path
import numpy as np
from PIL import Image
ROOT=Path(__file__).resolve().parents[1]; WORK=ROOT.parent
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(WORK/'tpe_rdh_reproduction'/'src'))
import block32_exact_order_authenticated_tpe as exact
import block32_authenticated_tpe as common
OUT=ROOT/'output'/'metrics'/'flowchart_exact_order_compensated'
RESULT=OUT/'cross_image_splice_test'
AUTH_KEY=hashlib.sha256(b'public reproducible research authentication key fixture').digest()
BLOCK=32

def main():
    RESULT.mkdir(parents=True,exist_ok=True)
    rows={r['image']:r for r in csv.DictReader((OUT/'metrics.csv').open(encoding='utf-8'))}
    assets={name:(r,np.asarray(Image.open(OUT/r['authenticated_png']).convert('RGB'),dtype=np.uint8),
                  (OUT/r['layout_sidecar']).read_bytes(),bytes.fromhex(r['image_id_hex']))
            for name,r in rows.items() if name in ('airplane','lena')}
    for name,(r,img,blob,iid) in assets.items():
        v=exact.verify_tpe_ciphertext(img,blob,AUTH_KEY,iid)
        if not v.accepted:raise AssertionError(f'clean {name} control failed: {v.reason}')
    if assets['airplane'][1].shape!=assets['lena'][1].shape:
        raise ValueError('Airplane and Lena authenticated outputs must have matching dimensions')

    # Both positions were screened so the recipient's reversible correction is
    # invertible and the case proceeds to HMAC verification/localization.
    cases=[('lena_to_airplane','airplane','lena',1,5),
           ('airplane_to_lena','lena','airplane',0,0)]
    results=[]
    for case,recipient_name,donor_name,by,bx in cases:
        _,recipient,sidecar,image_id=assets[recipient_name]
        donor=assets[donor_name][1]
        changed=recipient.copy(); y0,x0=by*BLOCK,bx*BLOCK
        changed[y0:y0+BLOCK,x0:x0+BLOCK,:]=donor[y0:y0+BLOCK,x0:x0+BLOCK,:]
        bid=by*(recipient.shape[1]//BLOCK)+bx
        affected=set()
        nblocks=(recipient.shape[0]//BLOCK)*(recipient.shape[1]//BLOCK)
        for c in range(3):
            for group in common._group_order(AUTH_KEY,c,nblocks):
                if bid in group:affected.add((c,int(group[0])))
        check=exact.verify_tpe_ciphertext(changed,sidecar,AUTH_KEY,image_id)
        detected=set(check.failed_groups)
        filename=f'{recipient_name}_with_{donor_name}_block_y{by}_x{bx}.png'
        Image.fromarray(changed).save(RESULT/filename)
        results.append({
            'case':case,'recipient':f'{recipient_name.title()} authenticated ciphertext',
            'donor':f'{donor_name.title()} authenticated ciphertext','block_origin_yx':f'{by},{bx}',
            'block_size':f'{BLOCK}x{BLOCK}','changed_RGB_pixels':BLOCK*BLOCK*3,
            'accepted':check.accepted,'failed_groups':repr(tuple(sorted(detected))),
            'expected_affected_groups':repr(tuple(sorted(affected))),
            'localization_exact':detected==affected,'plaintext_withheld':not check.accepted,
            'reason':check.reason,'tampered_image_file':filename})
        if check.accepted or detected!=affected:
            raise AssertionError(f'{case}: expected {sorted(affected)}, got {sorted(detected)}, accepted={check.accepted}')
    out=RESULT/'splice_results_bidirectional.csv'
    with out.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(results[0]),lineterminator='\n');w.writeheader();w.writerows(results)
    (RESULT/'README.txt').write_text(
        'Bidirectional controlled splice experiment. One authenticated 32x32 RGB block from the donor encrypted image was copied at the stated same coordinate into the recipient authenticated image. The recipient ImageID and AEAD-protected sidecar were used for verification. Clean Airplane and Lena recipient controls both verified before substitution. Both splices were rejected and exact affected four-block groups were reported, one per affected color channel; plaintext was withheld.\n',encoding='utf-8')
    print('Both splice directions rejected and localized exactly')
    for r in results:print(r['case'],r['failed_groups'])

if __name__=='__main__':main()
