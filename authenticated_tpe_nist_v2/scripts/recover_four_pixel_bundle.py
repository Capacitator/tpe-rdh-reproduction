#!/usr/bin/env python3
"""Verify/recover a saved four-pixel PNG + sidecar using keys from environment."""
from __future__ import annotations
import hashlib
import json
import os
import sys
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(REPO / "tpe_rdh_reproduction" / "src"))
import block32_exact_order_authenticated_tpe as exact
import four_pixel_pipeline as fourpx


def _key(name: str) -> bytes:
    text=os.environ.get(name, "")
    try:
        value=bytes.fromhex(text)
    except ValueError as exc:
        raise SystemExit(f"{name} must be 64 hexadecimal characters") from exc
    if len(value)!=32:
        raise SystemExit(f"{name} must decode to exactly 32 bytes")
    return value


def main() -> int:
    if len(sys.argv)!=3:
        raise SystemExit("usage: recover_four_pixel_bundle.py CIPHERTEXT.png SIDECAR.bin")
    image_path,sidecar_path=map(Path,sys.argv[1:])
    with Image.open(image_path) as image:
        marked=np.ascontiguousarray(np.asarray(image.convert("RGB"),dtype=np.uint8))
    result=exact.decrypt_authenticated_tpe_bundle(
        marked,sidecar_path.read_bytes(),_key("FOURPX_TPE_KEY_HEX"),
        _key("FOURPX_AUTH_KEY_HEX"),tpe_module=fourpx)
    if not result.accepted or result.recovered_image is None:
        print(json.dumps({"accepted":False,"reason":result.reason,
                          "failed_groups":[list(x) for x in result.failed_groups],
                          "recovered_image_withheld":True},separators=(",",":")))
        return 2
    print(json.dumps({"accepted":True,
                      "recovered_image_sha256":hashlib.sha256(
                          np.ascontiguousarray(result.recovered_image).tobytes()).hexdigest(),
                      "payload_bits":result.recovered_payload_bits,
                      "recovered_image_withheld":False},separators=(",",":")))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
