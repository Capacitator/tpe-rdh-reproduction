#!/usr/bin/env python3
"""Recreate the ignored 512x512 RGB inputs from tracked pixel-identical originals."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from PIL import Image

ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT.parent
SOURCE=ROOT/'output'/'metrics'/'visual_gallery'
DEST=ROOT/'input'/'images_512'
MAPPING=[('airplane','000_uct_airplane.png'),('baboon','001_uct_baboon.png'),
         ('couple','002_uct_couple.png'),('girl','003_uct_girl.png'),
         ('lena','004_uct_lena.png'),('peppers','005_uct_peppers.png')]

def main() -> None:
    DEST.mkdir(parents=True,exist_ok=True)
    records=[]
    for stem,name in MAPPING:
        source=SOURCE/f'{stem}_original.png'
        target=DEST/name
        if not source.is_file():
            raise FileNotFoundError(f'missing tracked reference image: {source}')
        with Image.open(source) as im:
            rgb=im.convert('RGB')
            if rgb.size!=(512,512):
                raise ValueError(f'{source} is {rgb.size}; expected 512x512')
            pixel_hash=hashlib.sha256(rgb.tobytes()).hexdigest()
            rgb.save(target,format='PNG')
        with Image.open(target) as check:
            reread=check.convert('RGB')
            if hashlib.sha256(reread.tobytes()).hexdigest()!=pixel_hash:
                raise IOError(f'RGB pixel verification failed after writing {target}')
            records.append({'input':name,'reference':str(source.relative_to(REPO)),
                            'width':512,'height':512,
                            'rgb_pixel_sha256':pixel_hash,
                            'png_file_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
                            'pixel_identical_to_reference':True,'write_readback_verified':True})
    manifest=DEST/'input_reconstruction_manifest.json'
    manifest.write_text(json.dumps({'inputs':records,'note':'RGB arrays match the tracked visual-gallery originals; PNG byte hashes may differ from the omitted experiment inputs.'},indent=2)+'\n')
    print(f'Prepared {len(records)} pixel-identical RGB inputs in {DEST}')
    print(f'Wrote {manifest}')

if __name__=='__main__': main()
