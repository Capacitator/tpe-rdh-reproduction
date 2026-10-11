#!/usr/bin/env python3
"""Run the exact-order, four-block authenticated TPE experiment on six inputs."""
from __future__ import annotations
import csv, hashlib, sys, time
from pathlib import Path
import numpy as np
from PIL import Image
from skimage.metrics import peak_signal_noise_ratio, structural_similarity

ROOT=Path(__file__).resolve().parents[1]
WORK=ROOT.parent
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(WORK/'tpe_rdh_reproduction'/'src'))
import block32_exact_order_authenticated_tpe as exact
import block32_authenticated_tpe as common
from pipeline import DemoPipelineParameters
from rdh import bits_from_bytes

INPUT=WORK/'tpe_rdh_reproduction'/'input'/'uct_colour'
OUT=ROOT/'output'/'metrics'/'flowchart_exact_order_compensated'
NAMES=['airplane','baboon','couple','girl','lena','peppers']
TPE_KEY=bytes.fromhex('00112233445566778899aabbccddeeff102132435465768798a9babbdcedfe0f')
AUTH_KEY=hashlib.sha256(b'public reproducible research authentication key fixture').digest()
PAYLOAD=bits_from_bytes(b'0123456789ABCDEF0123456789ABCDEF')


def psnr(a,b):
    return float('inf') if np.array_equal(a,b) else float(peak_signal_noise_ratio(a,b,data_range=255))


def block_sums(a,bs=32):
    h,w,_=a.shape
    x=a.reshape(h//bs,bs,w//bs,bs,3).astype(np.int64)
    return x.sum(axis=(1,3))


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    rows=[]; caprows=[]; manifest=[]
    for name in NAMES:
        started=time.time()
        with Image.open(INPUT/f'{name}.tif') as im:
            original=np.ascontiguousarray(np.asarray(im.convert('RGB'),dtype=np.uint8))
        iid=hashlib.sha256(b'flowchart-exact-order-image-id-v2\0'+name.encode()+original.tobytes()).digest()[:16]
        params=DemoPipelineParameters(block_size=32,key=TPE_KEY)
        base_result=common.legacy.encrypt_rgb_image(original,PAYLOAD,params)
        base=base_result.encrypted_image
        enc=exact.encrypt_authenticated_tpe(original,PAYLOAD,params,AUTH_KEY,iid)
        verification=exact.verify_tpe_ciphertext(enc.marked_image,enc.layout_sidecar,AUTH_KEY,iid)
        if not verification.accepted or not np.array_equal(verification.restored_tpe_ciphertext,base):
            raise AssertionError(f'{name}: authenticated removal did not restore exact TPE ciphertext')
        dec=exact.decrypt_authenticated_tpe(enc.marked_image,enc.layout_sidecar,params,AUTH_KEY,iid,
                                           enc.tpe_image_identifier,PAYLOAD)
        if not dec.accepted or dec.recovered_image is None or not np.array_equal(dec.recovered_image,original):
            raise AssertionError(f'{name}: exact recovery failed: {dec.reason}')
        if dec.recovered_payload_bits!=PAYLOAD:
            raise AssertionError(f'{name}: RDH payload mismatch')

        orig_thumb=common.block_thumbnail(original,32)
        base_thumb=common.block_thumbnail(base,32)
        final_thumb=common.block_thumbnail(enc.marked_image,32)
        base_sums=block_sums(base); final_sums=block_sums(enc.marked_image)
        abs_sum_delta=np.abs(final_sums-base_sums)
        if np.any(abs_sum_delta):
            raise AssertionError(f'{name}: compensated output changed a 32x32 per-channel block sum')
        base_path=OUT/f'{name}_block32_tpe.png'
        final_path=OUT/f'{name}_block32_authenticated_exact.png'
        orig_path=OUT/f'{name}_original.png'
        sidecar_path=OUT/f'{name}_layout.sidecar'
        for path,array in ((orig_path,original),(base_path,base),(final_path,enc.marked_image)):
            Image.fromarray(array,mode='RGB').save(path,format='PNG',optimize=True)
        sidecar_path.write_bytes(enc.layout_sidecar)
        for path in (orig_path,base_path,final_path,sidecar_path):
            manifest.append((hashlib.sha256(path.read_bytes()).hexdigest(),path.relative_to(OUT).as_posix()))

        rows.append({
            'image':name,'width':original.shape[1],'height':original.shape[0],'block_size':32,
            'group_tags':enc.group_count,'expected_group_tags':3*((original.shape[0]//32)*(original.shape[1]//32)//4),
            'minimum_group_capacity_bits':enc.minimum_group_capacity,
            'all_groups_capacity_at_least_256':min(enc.group_capacities)>=256,
            'authentication_accepted':dec.accepted,'exact_recovery':bool(np.array_equal(dec.recovered_image,original)),
            'payload_recovered':dec.recovered_payload_bits==PAYLOAD,
            'base_full_rgb_psnr_db':psnr(original,base),'final_full_rgb_psnr_db':psnr(original,enc.marked_image),
            'base_32x32_thumbnail_psnr_db':psnr(orig_thumb,base_thumb),
            'final_32x32_thumbnail_psnr_db':psnr(orig_thumb,final_thumb),
            'base_32x32_thumbnail_ssim':float(structural_similarity(orig_thumb,base_thumb,channel_axis=2,data_range=255)),
            'final_32x32_thumbnail_ssim':float(structural_similarity(orig_thumb,final_thumb,channel_axis=2,data_range=255)),
            'max_abs_block_sum_delta_auth_vs_base':int(abs_sum_delta.max()),
            'mean_abs_block_sum_delta_auth_vs_base':float(abs_sum_delta.mean()),
            'layout_sidecar_bytes':len(enc.layout_sidecar),
            'original_sha256':hashlib.sha256(original.tobytes()).hexdigest(),
            'base_tpe_sha256':hashlib.sha256(base.tobytes()).hexdigest(),
            'authenticated_image_sha256':hashlib.sha256(enc.marked_image.tobytes()).hexdigest(),
            'image_id_hex':iid.hex(),'tpe_image_identifier':str(enc.tpe_image_identifier),
            'original_png':orig_path.name,'base_tpe_png':base_path.name,
            'authenticated_png':final_path.name,'layout_sidecar':sidecar_path.name,
        })
        nblocks=(original.shape[0]//32)*(original.shape[1]//32)
        cursor=0
        for c in range(3):
            for gi,ids in enumerate(common._group_order(AUTH_KEY,c,nblocks)):
                cap=enc.group_capacities[cursor];cursor+=1
                caprows.append({'image':name,'channel':('R','G','B')[c],'group_index':gi,
                                'block_ids':' '.join(map(str,ids)),'net_rcm_capacity_bits':cap,
                                'required_tag_bits':256,'passes_capacity':cap>=256})
        if cursor!=len(enc.group_capacities):raise AssertionError('capacity audit row count mismatch')
        print(f"{name}: groups={enc.group_count}, min capacity={enc.minimum_group_capacity} bits, "
              f"thumbnail PSNR base/final={rows[-1]['base_32x32_thumbnail_psnr_db']:.4f}/"
              f"{rows[-1]['final_32x32_thumbnail_psnr_db']:.4f} dB, full RGB PSNR="
              f"{rows[-1]['final_full_rgb_psnr_db']:.4f} dB, exact={dec.accepted}, "
              f"time={time.time()-started:.1f}s",flush=True)

    for name,data in [('metrics.csv',rows),('group_capacity_audit.csv',caprows)]:
        with (OUT/name).open('w',newline='',encoding='utf-8') as f:
            writer=csv.DictWriter(f,fieldnames=list(data[0]),lineterminator='\n')
            writer.writeheader();writer.writerows(data)
    manifest.sort(key=lambda x:x[1])
    with (OUT/'SHA256SUMS.txt').open('w',encoding='utf-8') as f:
        for digest,path in manifest:f.write(f'{digest}  {path}\n')
    print(f'Wrote {len(rows)} image metric rows and {len(caprows)} group-capacity rows to {OUT}')

if __name__=='__main__':main()
