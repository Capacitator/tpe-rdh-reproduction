#!/usr/bin/env python3
"""Re-verify the delivered artifacts against their own recorded digests.

Checks, reading only files under ``output/`` and ``input/``:

1.  every ``.bin`` stream matches the SHA-256 in ``stream_manifest.csv``;
2.  every ASCII expansion of those streams matches ``ascii_sha256``;
3.  all 700 stream digests are pairwise distinct, in every category;
4.  the key/ImageID index partition is disjoint and complete;
5.  every raw official NIST file matches the SHA-256 in its category's
    ``raw_report_manifest.csv``, and every category has a non-empty
    ``finalAnalysisReport.txt``;
6.  the per-category counts are internally consistent
    (``first_level_pvalues.csv`` = 18,800 rows, summary counts add up);
7.  every file listed in ``SHA256SUMS.txt`` matches, and the file set matches;
8.  the streams reproduce the predefined definitions (recomputed digest of a
    freshly derived stream equals the stored one) for one stream per category.

Exit status is non-zero if any check fails.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
sys.path.insert(0, str(ROOT / "src"))

import streams as S  # noqa: E402

FAILURES: list[str] = []


def check(condition: bool, label: str) -> None:
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {label}")
    if not condition:
        FAILURES.append(label)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    manifest = list(csv.DictReader((OUT / "stream_manifest.csv").open(newline="")))
    print(f"1/8 stream digests ({len(manifest)} streams)")
    bad = [row["stream_file"] for row in manifest
           if sha256_file(ROOT / row["stream_file"]) != row["binary_sha256"]]
    check(not bad, f"every .bin matches binary_sha256 (mismatches: {len(bad)})")

    print("2/8 ASCII expansions")
    bad = []
    for row in manifest:
        payload = (ROOT / row["stream_file"]).read_bytes()
        if hashlib.sha256(S.stream_ascii(payload).encode("ascii")).hexdigest() != row["ascii_sha256"]:
            bad.append(row["stream_file"])
    check(not bad, f"every ascii_sha256 matches the MSB-first expansion (mismatches: {len(bad)})")

    print("3/8 independence")
    digests = [row["binary_sha256"] for row in manifest]
    per_category: dict[str, int] = {}
    for row in manifest:
        per_category.setdefault(row["category"], set()).add(row["binary_sha256"])
    check(len(set(digests)) == len(digests) == 700, "700 pairwise-distinct streams")
    check(all(len(values) == 100 for values in per_category.values())
          and len(per_category) == 7, "100 distinct streams in each of 7 categories")

    print("4/8 key partition")
    partition = S.key_partition_report()
    check(partition["disjoint"] and partition["key_indices_used"] == 3100,
          "3,100 disjoint UserKey/ImageID indices")

    print("5/8 raw official reports")
    for category in S.CATEGORY_ORDER:
        base = OUT / "categories" / category
        report_manifest = list(csv.DictReader((base / "raw_report_manifest.csv").open(newline="")))
        mismatched = [row["path"] for row in report_manifest
                      if sha256_file(ROOT / row["path"]) != row["sha256"]]
        final = OUT / "nist_raw" / category / "finalAnalysisReport.txt"
        check(not mismatched and final.is_file() and final.stat().st_size > 0,
              f"{category}: {len(report_manifest)} raw files verified, "
              f"finalAnalysisReport.txt {final.stat().st_size if final.is_file() else 0} bytes")

    print("6/8 per-category counts")
    for category in S.CATEGORY_ORDER:
        base = OUT / "categories" / category
        first = list(csv.DictReader((base / "first_level_pvalues.csv").open(newline="")))
        summary = list(csv.DictReader((base / "summary_counts.csv").open(newline="")))
        total = sum(int(row["pass"]) + int(row["fail"]) + int(row["not_applicable"])
                    for row in summary)
        passed = sum(int(row["pass"]) for row in summary)
        check(len(first) == 18_800 and total == 18_800
              and passed == sum(row["status"] == "pass" for row in first),
              f"{category}: {len(first)} first-level values, counts add up, "
              f"{passed} passes")

    print("7/8 SHA256SUMS coverage")
    sums_path = OUT / "SHA256SUMS.txt"
    listed = {}
    for line in sums_path.read_text().splitlines():
        digest, _, path = line.partition("  ")
        listed[path] = digest
    missing = [path for path in listed if not (ROOT / path).is_file()]
    mismatched = [path for path, digest in listed.items()
                  if (ROOT / path).is_file() and sha256_file(ROOT / path) != digest]
    on_disk = {str(p.relative_to(ROOT)) for p in OUT.rglob("*") if p.is_file()}
    ignored = {p for p in on_disk
               if p.endswith(".bin") or p.startswith("output/nist_input")
               or p.endswith("SHA256SUMS.txt")}
    uncovered = sorted(on_disk - set(listed) - ignored)
    check(not missing and not mismatched and not uncovered,
          f"{len(listed)} digests verified, {len(missing)} missing, "
          f"{len(mismatched)} mismatched, {len(uncovered)} uncovered output files")

    print("8/8 reproduction of the predefined definitions")
    for category in S.CATEGORY_ORDER:
        rows = [row for row in manifest if row["category"] == category]
        for row in (rows[0], rows[-1]):
            record = S._work((category, int(row["stream_index"])))
            fresh = hashlib.sha256(record.stream_bytes[:S.STREAM_BYTES]).hexdigest()
            check(fresh == row["binary_sha256"],
                  f"{category} stream {row['stream_index']} re-derives to the stored digest")

    independence = json.loads((OUT / "independence_checks.json").read_text())
    check(independence["ok"] and independence["duplicate_stream_count"] == 0,
          "independence_checks.json reports no duplicates")

    print()
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} check(s) FAILED")
        for failure in FAILURES:
            print(f"  - {failure}")
        return 1
    print("RESULT: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
