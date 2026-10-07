#!/usr/bin/env python3
"""Run authenticated-TPE-only 100-stream NIST STS 2.1.2 evaluation."""
from __future__ import annotations
import argparse,csv,hashlib,math,platform,re,shutil,subprocess,tempfile
from pathlib import Path
import numpy as np
from PIL import Image
P=Path(__file__).resolve().parents[1]; R=P.parent; O=P/'output/nist_sp800_22_improved'; I=R/'tpe_rdh_reproduction/input/uct_colour'
N=100; B=1_000_000; A=.01; IMGS=('airplane','baboon','couple','girl','lena','peppers')
CATS=('step2_image_derived_keyed_intermediate','final_marked_rgb')
TESTS=('Frequency','BlockFrequency','CumulativeSums','Runs','LongestRun','Rank','FFT','NonOverlappingTemplate','OverlappingTemplate','Universal','ApproximateEntropy','RandomExcursions','RandomExcursionsVariant','Serial','LinearComplexity')
def h(b): return hashlib.sha256(b).hexdigest()
def fixture(d,i,n): return hashlib.sha256(d+b'\0'+i.to_bytes(4,'big')).digest()[:n]
def load(n):
 p=I/f'{n}.tif'; f=h(p.read_bytes())
 with Image.open(p) as im:
  im=im.convert('RGB'); im=im if im.size==(512,512) else im.resize((512,512)); arr=np.asarray(im,dtype=np.uint8)
 return arr,f
def streams():
 import sys; sys.path.insert(0,str(P/'src')); import authenticated_tpe as auth
 from statistical_eval import pack_msb_first
 cache={n:load(n) for n in IMGS}; m=[]; seq={c:[] for c in CATS}; keys=[]; ids=[]
 for i in range(1,N+1):
  name=IMGS[(i-1)%6]; arr,source=cache[name]; key=fixture(b'auth-tpe-nist-key-v1',i,32); iid=fixture(b'auth-tpe-nist-image-id-v1',i,16)
  one=auth._step1_image(arr,key,iid); two=auth._step2_image(one,key); prot=auth.protect_image(arr,key,iid); dec=auth.verify_and_decrypt(prot.marked_image,key,iid)
  assert dec.accepted and np.array_equal(dec.recovered_image,arr)
  s2=pack_msb_first(two); fm=pack_msb_first(prot.marked_image); assert len(s2)==len(fm)==B
  sh,mh=h(s2.encode()),h(fm.encode()); kh,ih=h(key),h(iid); keys.append(kh);ids.append(ih)
  seq[CATS[0]].append(s2);seq[CATS[1]].append(fm)
  m.append(dict(stream_index=i,image=name,source_image_sha256=source,user_key_sha256=kh,image_id_sha256=ih,step2_sha256=h(two.tobytes(order='C')),final_marked_image_sha256=h(prot.marked_image.tobytes(order='C')),step2_stream_sha256=sh,final_marked_stream_sha256=mh,stream_length_bits=B,serialization_method='row-major C-order RGB uint8; MSB-first bit packing; first 1000000 bits',nist_version='2.1.2'))
 assert len(set(keys))==len(set(ids))==N
 for c in CATS: assert len({r['step2_stream_sha256'] if c==CATS[0] else r['final_marked_stream_sha256'] for r in m})==N
 return m,seq
def report_rows(p):
 rx=re.compile(r'^\s*(?:\d+\s+){10}(\d+(?:\.\d+)?|----)\s+\*?\s*(\d+/\d+|------)\s+\*?\s*([A-Za-z]+)\s*$')
 return [(x.group(3),x.group(1),x.group(2)) for l in p.read_text(errors='replace').splitlines() if (x:=rx.match(l))]
def assess(root,cat,seq):
 inp=O/f'.{cat}_input.txt';inp.write_text('\n'.join(seq)+'\n',encoding='ascii')
 ans=f'0\n{inp.resolve()}\n1\n0\n{N}\n0\n';p=subprocess.run([str(root/'assess'),str(B)],cwd=root,input=ans,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=7200)
 if 'Statistical Testing Complete' not in p.stdout: raise RuntimeError(p.stdout[-2500:])
 exp=root/'experiments/AlgorithmTesting'; out=O/f'{cat}_finalAnalysisReport.txt';shutil.copyfile(exp/'finalAnalysisReport.txt',out);out.write_text(out.read_text(errors='replace').replace(str(inp.resolve()),f'authenticated_tpe/output/nist_sp800_22_improved/{inp.name[1:]}')); inp.unlink()
 raw=O/f'{cat}_raw';shutil.rmtree(raw,ignore_errors=True);shutil.copytree(exp,raw);return out,raw
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--sts-dir',type=Path,required=True);args=ap.parse_args()
 cands=[args.sts_dir,args.sts_dir/'sts',args.sts_dir/'sts-2.1.2',args.sts_dir/'sts-2.1.2/sts-2.1.2'];src=next((x.resolve() for x in cands if (x/'assess').is_file()),None)
 if src is None: raise FileNotFoundError('built official STS assess not found')
 O.mkdir(parents=True,exist_ok=True);manifest,seq=streams()
 with (O/'stream_manifest.csv').open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(manifest[0]));w.writeheader();w.writerows(manifest)
 temp=Path(tempfile.mkdtemp(prefix='.sts_runtime_',dir=O));root=temp/'sts';shutil.copytree(src,root,dirs_exist_ok=True);reports={}
 try:
  for cat in CATS: reports[cat]=assess(root,cat,seq[cat])
  fields=['category','image','stream_index','test_name','component','p_value','status','pass_proportion','alpha','stream_length_bits','nist_version'];rows=[];summary=[]
  for cat,(rp,raw) in reports.items():
   ss=report_rows(rp); names=list(dict.fromkeys(z[0] for z in ss)); assert set(names)==set(TESTS),(names,cat)
   for test in names:
    specs=[x for x in ss if x[0]==test]; ncomp=len(specs); vals=[];rf=raw/test/'results.txt'
    if rf.exists():
     for t in rf.read_text(errors='replace').split():
      try:vals.append(float(t))
      except ValueError:pass
    excursions=test in ('RandomExcursions','RandomExcursionsVariant'); symbols=(list(range(-4,0))+list(range(1,5))) if test=='RandomExcursions' else (list(range(-9,0))+list(range(1,10))) if test=='RandomExcursionsVariant' else []
    stat=raw/test/'stats.txt';blocks=stat.read_text(errors='replace').split('RANDOM EXCURSIONS TEST' if test=='RandomExcursions' else 'RANDOM EXCURSIONS VARIANT TEST')[1:] if excursions and stat.exists() else []
    for comp,(nm,uniform,prop) in enumerate(specs):
     for ix,m in enumerate(manifest):
      pv=None
      if excursions:
       if ix<len(blocks) and 'TEST NOT APPLICABLE' not in blocks[ix]:
        pvls=re.findall(r'p[-_]value\s*=\s*([0-9.eE+-]+)',blocks[ix]);pv=float(pvls[comp]) if comp<len(pvls) else None
       component=f'state={symbols[comp]}'
      else:
       pos=comp*N+ix if len(vals)==N*ncomp else (ix*ncomp+comp if len(vals)==N*ncomp else -1);pv=vals[pos] if 0<=pos<len(vals) else None;component=f'component={comp+1}'
      status='not-applicable' if pv is None or not math.isfinite(pv) else 'pass' if pv>=A else 'fail'
      rows.append(dict(category=cat,image=m['image'],stream_index=m['stream_index'],test_name=test,component=component,p_value='' if pv is None else f'{pv:.10g}',status=status,pass_proportion=prop,alpha=A,stream_length_bits=B,nist_version='2.1.2'))
    subset=[x for x in rows if x['category']==cat and x['test_name']==test]
    summary.append(dict(category=cat,test_name=test,component_count=ncomp,pass_count=sum(x['status']=='pass' for x in subset),fail_count=sum(x['status']=='fail' for x in subset),not_applicable_count=sum(x['status']=='not-applicable' for x in subset),uniformity_p_values='|'.join(x[1] for x in specs),pass_proportions='|'.join(x[2] for x in specs),alpha=A))
  for fn,data in [('results.csv',rows),('per_test_summary.csv',summary)]:
   with (O/fn).open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(data[0]));w.writeheader();w.writerows(data)
  # Preserve compact native reports plus NIST final analysis reports; do not leave large intermediate runtime outputs.
  for cat,(_,raw) in reports.items():
   d=O/f'{cat}_raw_reports';shutil.rmtree(d,ignore_errors=True);d.mkdir(exist_ok=True)
   for test in TESTS:
    td=raw/test
    if td.exists():
     dest=d/test;dest.mkdir(exist_ok=True)
     for nm in ('results.txt','stats.txt'):
      if (td/nm).exists():shutil.copyfile(td/nm,dest/nm)
  counts={c:{s:sum(x['category']==c and x['status']==s for x in rows) for s in ('pass','fail','not-applicable')} for c in CATS}
  lines=['NIST SP 800-22 Rev. 1a results from official STS 2.1.2.','100 streams/category; 1000000 bits/stream; alpha=0.01.','Step-2 is an image-derived keyed intermediate, not chaotic. No overall pass is claimed.','SP 800-22 is a statistical diagnostic, not a cryptographic proof.']
  for c in CATS:
   lines+=['',f'[{c}] totals={counts[c]}','| Test | Pass | Fail | N/A | Uniformity p-value(s) | Pass proportion(s) |','|---|---:|---:|---:|---|---|']
   for x in [q for q in summary if q['category']==c]:lines.append(f"| {x['test_name']} | {x['pass_count']} | {x['fail_count']} | {x['not_applicable_count']} | {x['uniformity_p_values']} | {x['pass_proportions']} |")
  (O/'summary.txt').write_text('\n'.join(lines)+'\n')
  (O/'ADAPTED_EXPERIMENT_NOTE.txt').write_text('Six public UCT images (airplane, baboon, couple, girl, lena, peppers) were used because the exact eight CelebA-HQ files were unavailable. 100 unique deterministic UserKey and ImageID fixtures were used. Step-2 is an image-derived keyed intermediate, not chaotic. No overall NIST pass is claimed. SP 800-22 is a statistical diagnostic, not a cryptographic proof.\n')
  assess_hash=h((root/'assess').read_bytes()); runner_hash=h(Path(__file__).read_bytes());commit=subprocess.check_output(['git','-C',str(R),'rev-parse','HEAD'],text=True).strip()
  prov=['experiment=authenticated-TPE-only improved NIST evaluation','nist_sts_version=2.1.2',f'nist_assess_sha256={assess_hash}',f'runner_script_sha256={runner_hash}',f'source_commit={commit}','streams_per_category=100','stream_length_bits=1000000','alpha=0.01','image_selection=round-robin airplane,baboon,couple,girl,lena,peppers','fixture_derivation=domain-separated SHA-256 deterministic fixtures; only digests recorded','serialization=row-major C-order RGB uint8; MSB-first; first 1000000 bits','categories='+','.join(CATS),'tests='+','.join(TESTS),'command=python authenticated_tpe/experiments/run_nist_sp800_22_improved.py --sts-dir <official NIST STS 2.1.2 directory>','No key or ImageID bytes are written; SHA-256 digests only.']
  (O/'provenance.txt').write_text('\n'.join(prov)+'\n')
  for cat,(_,raw) in reports.items():shutil.rmtree(raw,ignore_errors=True)
  print('NIST_COUNTS',counts,'ROWS',len(rows),'SUMMARY_ROWS',len(summary))
 finally:shutil.rmtree(temp,ignore_errors=True)
if __name__=='__main__':main()
