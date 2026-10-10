#!/usr/bin/env python3
"""Targeted re-test of the sum-class reduction with a much larger sample.

``output/metrics/class_uniformity.csv`` screens every distinct sum-class size with
200,000 PRF words and reports two sizes with an uncorrected p < 0.01 (1.28
expected over 128 sizes, none surviving Holm correction).  A screening result is
not evidence, so the sizes that looked marginal are re-tested here with 1,048,576
independent draws.  The outcome is written to
``output/metrics/class_uniformity_retest.csv`` whatever it is.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import sys
from pathlib import Path

import numpy as np
from scipy.stats import chisquare

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import atpe_v2 as v2  # noqa: E402
import streams as S  # noqa: E402

OUT = ROOT / "output" / "metrics" / "class_uniformity_retest.csv"
SIZES = (4, 86, 142, 255, 256, 3, 7)
DRAWS = 1_048_576


def words(count: int) -> np.ndarray:
    prefix_cache: dict[int, bytes] = {}
    out = np.empty(count, dtype=np.uint64)
    filled = 0
    instance = 0
    while filled < count:
        key = S.pool_key(12000 + instance)
        image_id = S.pool_image_id(12000 + instance)
        ktpe = v2.derive_keys(key, 0)["Ktpe"]
        prefix = prefix_cache.setdefault(id(ktpe), b"tpe-shift" + image_id)
        stop = False
        for block in range(256):
            block_bytes = block.to_bytes(2, "big")
            for pair in range(512):
                if filled >= count:
                    stop = True
                    break
                digest = hmac.new(ktpe, prefix + block_bytes + pair.to_bytes(2, "big"),
                                  hashlib.sha256).digest()
                out[filled] = int.from_bytes(digest[:4], "big")
                filled += 1
            if stop:
                break
        instance += 1
    return out


def main() -> None:
    print(f"drawing {DRAWS} independent PRF words across disjoint instances ...", flush=True)
    sample = words(DRAWS)
    rows = []
    for size in SIZES:
        counts = np.bincount(sample % size, minlength=size)
        statistic, p_value = chisquare(counts)
        rows.append({"class_size": size, "draws": int(sample.size),
                     "chi_square": float(statistic), "p_value": float(p_value),
                     "uniform_at_0.01": bool(p_value >= 0.01),
                     "rejection_branch_active": bool((1 << 32) % size != 0)})
        print(f"  class_size={size:4d} chi2={statistic:10.3f} p={p_value:.6f} "
              f"uniform={p_value >= 0.01}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()