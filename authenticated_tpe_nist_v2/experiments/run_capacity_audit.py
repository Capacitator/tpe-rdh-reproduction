#!/usr/bin/env python3
"""Recompute whole-image and 4-block RCM capacity for all six test images."""
from __future__ import annotations
import csv,hashlib,sys
from pathlib import Path
import numpy as np
from PIL import Image
ROOT=Path(__file__).resolve().parents[1];REPO=ROOT.parent
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(REPO/'tpe_rdh_reproduction'/'src'))
import block32_authenticated_tpe as h
from pipeline import DemoPipelineParameters,generate_upsilon_matrices
from permutation import permute_image_blocks
from rdh import embed_bits,bits_from_bytes

NAMES=['airplane','baboon','couple','girl','lena','peppers']
INPUT=REPO/'tpe_rdh_reproduction'/'input'/'uct_colour'
OUT=ROOT/'output'/'metrics'/'flowchart_hybrid'
TPE_KEY=bytes.fromhex('00112233445566778899aabbccddeeff102132435465768798a9babbdcedfe0f')
AUTH_KEY=hashlib.sha256(b'public reproducible research authentication key fixture').digest()
PAYLOAD=bits_from_bytes(b'0123456789ABCDEF0123456789ABCDEF')

def counts(a,c=None,bids=None):
 out={'T':0,'O':0,'N':0}
 channels=range(3) if c is None else [c]
 for ch in channels:
  use=range((a.shape[0]//32)*(a.shape[1]//32)) if bids is None else bids
  for bid in use:
   for k in range(512):out[h.auth_primitives.classify_pair(*h._get_pair(a,ch,bid,k))]+=1
 return out

def net(q):return q['T']+q['O']-q['N']

def main():
 rows=[]
 for name in NAMES:
  with Image.open(INPUT/f'{name}.tif') as im:a=np.ascontiguousarray(np.asarray(im.convert('RGB'),dtype=np.uint8))
  iid=hashlib.sha256(b'flowchart-hybrid-image-id-v1\0'+name.encode()+a.tobytes()).digest()[:16]
  params=DemoPipelineParameters(block_size=32,key=TPE_KEY)
  imageid=h.legacy._resolve_encryption_identifier(a,params.image_identifier)
  up,us=generate_upsilon_matrices(*a.shape[:2],params.key,imageid)
  perm=permute_image_blocks(a,up,32)
  parts=h.legacy._split_payload_across_channels(PAYLOAD,3)
  carrier=np.stack([embed_bits(perm[:,:,c],parts[c])[0] for c in range(3)],axis=2)
  step1=h._auth_step1(carrier,AUTH_KEY,iid)
  step2=h._auth_step2(step1,AUTH_KEY)
  legacy_cipher=h.legacy.encrypt_rgb_image(a,PAYLOAD,params).encrypted_image
  total=counts(step2);oldtotal=counts(legacy_cipher)
  ng=(a.shape[0]//32)*(a.shape[1]//32);group_nets=[]
  for c in range(3):
   for ids in h._group_order(AUTH_KEY,c,ng):group_nets.append(net(counts(step2,c,ids)))
  row={'image':name,'dims':f'{a.shape[1]}x{a.shape[0]}','post_step2_T':total['T'],'post_step2_O':total['O'],'post_step2_N':total['N'],'post_step2_whole_net_capacity_bits':net(total),'groups_total':len(group_nets),'groups_with_capacity_ge_256':sum(x>=256 for x in group_nets),'groups_below_256':sum(x<256 for x in group_nets),'minimum_four_block_net_capacity':min(group_nets),'median_four_block_net_capacity':float(np.median(group_nets)),'legacy_after_substitution_whole_net_capacity_bits':net(oldtotal)}
  rows.append(row)
  print(f"{name}: whole net={row['post_step2_whole_net_capacity_bits']}; groups≥256={row['groups_with_capacity_ge_256']}/{row['groups_total']}; legacy post-substitution net={row['legacy_after_substitution_whole_net_capacity_bits']}")
 OUT.mkdir(parents=True,exist_ok=True)
 with (OUT/'capacity_audit.csv').open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)
 print(f'Wrote {OUT}/capacity_audit.csv')
if __name__=='__main__':main()
