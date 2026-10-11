#!/usr/bin/env python3
"""Write provenance.json and SHA256SUMS.txt for the flowchart hybrid outputs."""
from __future__ import annotations
import csv,hashlib,json,platform,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];REPO=ROOT.parent
OUT=ROOT/'output'/'metrics'/'flowchart_hybrid'
REPORT=ROOT/'output'/'metrics'/'block32_corrected_images'/'professor_32x32_block_effect_gallery.docx'

def sha(p:Path):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()

def git(*args):
 try:return subprocess.check_output(['git',*args],cwd=REPO,text=True,stderr=subprocess.DEVNULL).strip()
 except Exception:return 'unavailable'

def main():
 code=[ROOT/'src'/'block32_authenticated_tpe.py',ROOT/'experiments'/'run_flowchart_hybrid.py',ROOT/'experiments'/'run_capacity_audit.py',ROOT/'experiments'/'append_flowchart_results_to_gallery.py',ROOT/'experiments'/'write_flowchart_provenance.py',ROOT/'tests'/'test_block32_authenticated_tpe.py',REPO/'tpe_rdh_reproduction'/'src'/'pipeline.py',REPO/'tpe_rdh_reproduction'/'src'/'permutation.py',REPO/'tpe_rdh_reproduction'/'src'/'substitution.py',REPO/'tpe_rdh_reproduction'/'src'/'rdh.py',ROOT/'src'/'atpe_v2.py']
 inputs=[REPO/'tpe_rdh_reproduction'/'input'/'uct_colour'/f'{n}.tif' for n in ['airplane','baboon','couple','girl','lena','peppers']]
 rows=list(csv.DictReader((OUT/'metrics.csv').open(newline='',encoding='utf-8')))
 p={
  'generated_utc':datetime.now(timezone.utc).isoformat(),
  'branch':git('branch','--show-current'),
  'code_commit':git('log','-1','--format=%H','--','authenticated_tpe_nist_v2/src/block32_authenticated_tpe.py'),
  'python':platform.python_version(),'platform':platform.platform(),
  'protocol':'32x32 block-TPE/RDH plus HMAC-SHA256, HMAC_DRBG grouping, reversible RCM authentication, and outer reversible pair-sum-preserving legacy substitution',
  'image_count':len(rows),'all_exact_recovery':all(r['exact_recovery']=='True' for r in rows),
  'all_authentication_accepted':all(r['authentication_accepted']=='True' for r in rows),
  'authentication_modes':{m:sum(r['auth_mode']==m for r in rows) for m in sorted({r['auth_mode'] for r in rows})},
  'test_keys':'fixed public reproducibility fixtures in run_flowchart_hybrid.py; not secrets',
  'psnr_definition':'Full RGB PSNR: original array vs encrypted array. Block-thumbnail PSNR: rounded RGB mean per corresponding 32x32 block.',
  'source_hashes_sha256':{str(p.relative_to(REPO)):sha(p) for p in code+inputs},
  'report_sha256':sha(REPORT),
  'output_files_sha256':{}
 }
 # Hash every completed output except the manifest being generated.
 for f in sorted(OUT.rglob('*')):
  if f.is_file() and f.name not in ('SHA256SUMS.txt','provenance.json'):
   p['output_files_sha256'][f.relative_to(OUT).as_posix()]=sha(f)
 (OUT/'provenance.json').write_text(json.dumps(p,indent=2,sort_keys=True)+'\n',encoding='utf-8')
 lines=[f"{v}  {k}" for k,v in p['output_files_sha256'].items()]
 lines.append(f"{p['report_sha256']}  ../block32_corrected_images/professor_32x32_block_effect_gallery.docx")
 (OUT/'SHA256SUMS.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
 print(f"Wrote {OUT/'provenance.json'} and {OUT/'SHA256SUMS.txt'}")
 print('images=',p['image_count'],'all_recovery=',p['all_exact_recovery'],'all_auth=',p['all_authentication_accepted'],'modes=',p['authentication_modes'])
if __name__=='__main__':main()
