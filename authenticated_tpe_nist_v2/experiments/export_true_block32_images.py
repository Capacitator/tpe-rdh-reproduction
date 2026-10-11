#!/usr/bin/env python3
"""Regenerate professor-requested 32x32 block-encrypted examples.

IMPORTANT: This invokes the separate chaotic TPE/RDH reproduction pipeline,
not the authenticated block-group prototype. The source method specifies block
permutation and substitution; the authenticated scheme has no spatial block
permutation, so it cannot produce this same visual block effect without a
method change. Every output here is a fresh, validated run of the original
TPE/RDH implementation at b=32; no pixels are post-processed for appearance.
"""
from __future__ import annotations
import csv, hashlib, sys
from pathlib import Path
from dataclasses import replace
import numpy as np
from PIL import Image

AUTH_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = AUTH_ROOT.parent
LEGACY = REPO_ROOT / "tpe_rdh_reproduction"
sys.path.insert(0, str(LEGACY / "src"))
from pipeline import DemoPipelineParameters, block_sums, decrypt_rgb_image, encrypt_rgb_image
from rdh import bits_from_bytes

INPUT = LEGACY / "input" / "uct_colour"
OUTPUT = AUTH_ROOT / "output" / "metrics" / "block32_corrected_images"
NAMES = ["airplane", "baboon", "couple", "girl", "lena", "peppers"]
PAYLOAD = bits_from_bytes(b"0123456789ABCDEF0123456789ABCDEF")


def sha(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""): h.update(b)
    return h.hexdigest()


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    rows=[]
    for name in NAMES:
        src=INPUT/f"{name}.tif"
        if not src.is_file(): raise FileNotFoundError(src)
        with Image.open(src) as im:
            original=np.asarray(im.convert("RGB"),dtype=np.uint8)
        params=DemoPipelineParameters(block_size=32)
        encrypted=encrypt_rgb_image(original,PAYLOAD,params)
        decrypt=decrypt_rgb_image(encrypted,replace(params,image_identifier=encrypted.image_identifier))
        assert np.array_equal(decrypt.recovered_image,original),f"recovery failed {name}"
        assert decrypt.payload_bits==PAYLOAD,f"payload recovery failed {name}"
        assert np.array_equal(block_sums(encrypted.marked_image,32),block_sums(encrypted.encrypted_image,32)),f"b=32 sums not preserved {name}"
        p=OUTPUT/f"{name}_block32_encrypted.png"
        Image.fromarray(encrypted.encrypted_image,mode="RGB").save(p,format="PNG",optimize=True)
        srcout=OUTPUT/f"{name}_original.png"
        Image.fromarray(original,mode="RGB").save(srcout,format="PNG",optimize=True)
        rows.append({"image":name,"block_size":32,"width":original.shape[1],"height":original.shape[0],"exact_recovery":True,"payload_recovered":True,"thumbnail_block_sums_preserved":True,"input_sha256":hashlib.sha256(original.tobytes()).hexdigest(),"encrypted_pixel_sha256":hashlib.sha256(encrypted.encrypted_image.tobytes()).hexdigest(),"original_png":srcout.name,"encrypted_png":p.name,"encrypted_png_sha256":sha(p)})
        print(f"{name}: b=32, exact recovery, payload, and block sums verified; {p}")
    with (OUTPUT/"manifest.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator="\n");w.writeheader();w.writerows(rows)
    (OUTPUT/"README.txt").write_text("These are regenerated, genuine block_size=32 ciphertext outputs from the separate tpe_rdh_reproduction chaotic TPE/RDH pipeline. They are not outputs of authenticated_tpe_nist_v2. The authenticated block-group method has no spatial block permutation, so it is not expected to produce the same block effect. No post-processing was applied. Re-run: python3 experiments/export_true_block32_images.py. Every image was validated for exact recovery, payload recovery, and preserved 32x32 per-channel block sums.\n",encoding="utf-8")
    print(f"Completed {len(rows)} verified images; manifest={OUTPUT/'manifest.csv'}")

if __name__=="__main__": main()
