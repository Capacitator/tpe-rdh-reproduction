#!/usr/bin/env python3
"""Run the separate flowchart-aligned authenticated block-TPE experiment."""
from __future__ import annotations
import csv, hashlib, sys
from pathlib import Path
import numpy as np
from PIL import Image
from skimage.metrics import peak_signal_noise_ratio, structural_similarity
ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT.parent
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(REPO/'tpe_rdh_reproduction'/'src'))
import block32_authenticated_tpe as hybrid
from pipeline import DemoPipelineParameters
from rdh import bits_from_bytes
INPUT=REPO/'tpe_rdh_reproduction'/'input'/'uct_colour'
OUT=ROOT/'output'/'metrics'/'flowchart_hybrid'
NAMES=['airplane','baboon','couple','girl','lena','peppers']
TPE_KEY=bytes.fromhex('00112233445566778899aabbccddeeff102132435465768798a9babbdcedfe0f')
AUTH_KEY=hashlib.sha256(b"public reproducible research authentication key fixture").digest()
PAYLOAD=bits_from_bytes(b"0123456789ABCDEF0123456789ABCDEF")


def psnr(a,b):
 return float('inf') if np.array_equal(a,b) else float(peak_signal_noise_ratio(a,b,data_range=255))

def main():
 OUT.mkdir(parents=True,exist_ok=True); rows=[]
 for name in NAMES:
  with Image.open(INPUT/f'{name}.tif') as im: original=np.ascontiguousarray(np.asarray(im.convert('RGB'),dtype=np.uint8))
  iid=hashlib.sha256(b'flowchart-hybrid-image-id-v1\0'+name.encode()+original.tobytes()).digest()[:16]
  params=DemoPipelineParameters(block_size=32,key=TPE_KEY)
  enc=hybrid.encrypt_authenticated_tpe(original,PAYLOAD,params,AUTH_KEY,iid)
  dec=hybrid.decrypt_authenticated_tpe(enc.marked_image,PAYLOAD,params,AUTH_KEY,iid,enc.tpe_image_identifier)
  if not dec.accepted or dec.recovered_image is None or not np.array_equal(dec.recovered_image,original):
   raise AssertionError(f'{name}: authentication/recovery failed: {dec.reason}')
  base=hybrid.legacy.encrypt_rgb_image(original,PAYLOAD,params)
  # Existing reversible Step 2 preserves block sums of its actual input carrier.
  step2_roundtrip=np.array_equal(
   hybrid.legacy.decrypt_rgb_image(base,params).recovered_image,original)
  if not step2_roundtrip: raise AssertionError(f'{name}: source TPE standalone check failed')
  orig_thumb=hybrid.block_thumbnail(original,32)
  base_thumb=hybrid.block_thumbnail(base.encrypted_image,32)
  final_thumb=hybrid.block_thumbnail(enc.marked_image,32)
  paths={
   'original':OUT/f'{name}_original.png',
   'base':OUT/f'{name}_block32_tpe.png',
   'final':OUT/f'{name}_block32_authenticated.png',
  }
  for key,array in [('original',original),('base',base.encrypted_image),('final',enc.marked_image)]:
   Image.fromarray(array,mode='RGB').save(paths[key],format='PNG',optimize=True)
  rows.append({
   'image':name,'width':original.shape[1],'height':original.shape[0],'block_size':32,
   'auth_mode':enc.auth_mode,'authentication_groups_or_whole_tags':enc.groups,
   'authentication_accepted':dec.accepted,'exact_recovery':bool(np.array_equal(dec.recovered_image,original)),
   'payload_recovered':dec.recovered_payload_bits==PAYLOAD,
   'base_ciphertext_full_rgb_psnr_db':psnr(original,base.encrypted_image),
   'authenticated_ciphertext_full_rgb_psnr_db':psnr(original,enc.marked_image),
   'base_block_thumbnail_psnr_db':psnr(orig_thumb,base_thumb),
   'authenticated_block_thumbnail_psnr_db':psnr(orig_thumb,final_thumb),
   'base_block_thumbnail_ssim':float(structural_similarity(orig_thumb,base_thumb,channel_axis=2,data_range=255)),
   'authenticated_block_thumbnail_ssim':float(structural_similarity(orig_thumb,final_thumb,channel_axis=2,data_range=255)),
   'input_pixel_sha256':hashlib.sha256(original.tobytes()).hexdigest(),
   'base_ciphertext_pixel_sha256':hashlib.sha256(base.encrypted_image.tobytes()).hexdigest(),
   'authenticated_ciphertext_pixel_sha256':hashlib.sha256(enc.marked_image.tobytes()).hexdigest(),
   'image_id_hex':iid.hex(),
   'original_png':paths['original'].name,'base_ciphertext_png':paths['base'].name,
   'authenticated_ciphertext_png':paths['final'].name,
  })
  print(f"{name}: mode={enc.auth_mode}, exact={dec.accepted}, full PSNR base/final={rows[-1]['base_ciphertext_full_rgb_psnr_db']:.4f}/{rows[-1]['authenticated_ciphertext_full_rgb_psnr_db']:.4f} dB, block-thumbnail PSNR base/final={rows[-1]['base_block_thumbnail_psnr_db']:.4f}/{rows[-1]['authenticated_block_thumbnail_psnr_db']:.4f} dB")
 with (OUT/'metrics.csv').open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)
 (OUT/'README.md').write_text(
  '# Flowchart hybrid experiment\n\n'
  'The old TPE stage produces a thumbnail-preserving block permutation/RDH carrier. The authenticated method applies its reversible pair Step-1/Step-2, HMAC-SHA256, HMAC-DRBG block grouping and RCM tag marking at that capacity-adequate carrier stage. The old TPE pair-sum-preserving substitution is applied as an outer reversible transform after RCM; decryption inverts it before HMAC verification. This ordering adjustment is required because the legacy substitution ciphertext has negative RCM net capacity (see CAPACITY_AUDIT.md). No original source code was overwritten.\n\n'
  'PSNR is reported both on full-resolution RGB pixels (original vs encrypted; not the thumbnail-preservation score) and on rounded 32x32 block-average RGB thumbnails. The latter directly measures thumbnail fidelity. SSIM is reported for thumbnails. Identifiers and keys in this experiment are reproducible public test fixtures, not production secrets.\n',encoding='utf-8')
 print(f'Wrote {len(rows)} image rows to {OUT}/metrics.csv')
if __name__=='__main__':main()
