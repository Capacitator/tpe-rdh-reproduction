#!/usr/bin/env python3
"""Aggregate the corrected NIST run per (category, test) and build before/after.

Outputs
-------
``output/nist_per_test_summary.csv``
    One row per (category, test): component count, second-level uniformity
    p-value range, pass/fail/not-applicable counts over every first-level
    p-value, and the suite's own printed uniformity value and pass proportion.
``output/before_after.csv``
    The original document's Table 7 outcomes next to the corrected outcomes for
    the cryptographic-component streams, plus a diagnostic comparison.
``output/headline_counts.csv``
    Totals per category (first-level pass/fail/not-applicable).
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
REPO = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))

import nist_runner as N  # noqa: E402
import streams as S  # noqa: E402

ALPHA = S.ALPHA

# The original document's Table 7 row labels -> canonical STS test names.
BEFORE_LABEL_MAP = {
    "Frequency Test": "Frequency",
    "Block Frequency Test": "BlockFrequency",
    "Runs Test": "Runs",
    "Longest Run of Ones Test": "LongestRun",
    "Binary Matrix Rank Test": "Rank",
    "Discrete Fourier Transform Test": "FFT",
    "Non-overlapping Template Matching Test": "NonOverlappingTemplate",
    "Overlapping Template Matching Test": "OverlappingTemplate",
    "Maurer's Universal Statistical Test": "Universal",
    "Linear Complexity Test": "LinearComplexity",
    "Serial Test": "Serial",
    "Approximate Entropy Test": "ApproximateEntropy",
    "Cumulative Sums Test": "CumulativeSums",
    "Random Excursions Test": "RandomExcursions",
    "Random Excursions Variant Test": "RandomExcursionsVariant",
}
BEFORE_COLUMNS = ("Step-2 intermediate", "Final marked image")


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def before_table_from_docx(path: Path) -> dict[str, dict[str, dict]]:
    """Read the original document's Table 7 cells verbatim."""
    import docx

    document = docx.Document(str(path))
    table = None
    for candidate in document.tables:
        header = [cell.text.strip() for cell in candidate.rows[0].cells]
        if header and header[0].lower().startswith("nist test"):
            table = candidate
            break
    if table is None:
        raise SystemExit("original Table 7 not found in the supplied document")
    out: dict[str, dict[str, dict]] = {}
    column = {1: BEFORE_COLUMNS[0], 3: BEFORE_COLUMNS[1]}
    for row in table.rows[1:]:
        cells = [cell.text.strip() for cell in row.cells]
        test = BEFORE_LABEL_MAP.get(cells[0])
        if test is None:
            continue
        entry = {}
        for index, name in column.items():
            entry[name] = {"p_value": cells[index], "result": cells[index + 1]}
        out[test] = entry
    return out


def aggregate_category(category: str) -> list[dict]:
    base = OUT / "categories" / category
    first = read_csv(base / "first_level_pvalues.csv")
    second = read_csv(base / "second_level_uniformity.csv")
    suite_by_test: dict[str, list[dict]] = {}
    for row in second:
        suite_by_test.setdefault(row["test_name"], []).append(row)

    rows = []
    tests = list(dict.fromkeys(row["test_name"] for row in first))
    for test in tests:
        records = [row for row in first if row["test_name"] == test]
        passed = sum(row["status"] == "pass" for row in records)
        failed = sum(row["status"] == "fail" for row in records)
        na = sum(row["status"] == "not-applicable" for row in records)
        values = [float(row["p_value"]) for row in records if row["p_value"] not in ("", None)]
        suite = suite_by_test.get(test, [])
        suite_p = [row["suite_p_value"] for row in suite if row["suite_p_value"] not in ("", "----")]
        suite_prop = [row["suite_pass_proportion"] for row in suite
                      if row["suite_pass_proportion"] not in ("", "N/A", "----", "------")]
        recomputed = [row["recomputed_uniformity_p_value"] for row in suite
                      if row["recomputed_uniformity_p_value"] not in ("", None)]
        suite_bins = [sum(int(row[f"C{i + 1}"]) for row in suite) for i in range(10)] if suite else [0] * 10
        rows.append({
            "category": category,
            "kind": S.CATEGORY_KIND[category],
            "test": test,
            "test_label": N.TEST_LABELS[test],
            "components": len(suite) if suite else 1,
            "first_level_count": len(records),
            "pass": passed, "fail": failed, "not_applicable": na,
            "pass_proportion": round(passed / (passed + failed), 6) if (passed + failed) else "",
            "min_first_level_p": f"{min(values):.12g}" if values else "",
            "max_first_level_p": f"{max(values):.12g}" if values else "",
            "median_first_level_p": f"{float(np.median(values)):.12g}" if values else "",
            "suite_uniformity_p_min": min(suite_p, key=float) if suite_p else "",
            "suite_uniformity_p_max": max(suite_p, key=float) if suite_p else "",
            "recomputed_uniformity_p_min":
                f"{min(float(x) for x in recomputed):.12g}" if recomputed else "",
            "recomputed_uniformity_p_max":
                f"{max(float(x) for x in recomputed):.12g}" if recomputed else "",
            "suite_pass_proportion_reported": ";".join(dict.fromkeys(suite_prop)),
            "histogram_bins_C1..C10": ";".join(str(x) for x in suite_bins),
        })
    return rows


def main() -> None:
    per_test: list[dict] = []
    headline: list[dict] = []
    for category in S.CATEGORY_ORDER:
        if not (OUT / "categories" / category).is_dir():
            print(f"[skip] {category}: not run yet")
            continue
        rows = aggregate_category(category)
        per_test.extend(rows)
        first = read_csv(OUT / "categories" / category / "first_level_pvalues.csv")
        headline.append({
            "category": category, "kind": S.CATEGORY_KIND[category],
            "title": S.CATEGORY_TITLE[category],
            "streams": S.STREAM_COUNT, "bits_per_stream": S.STREAM_BITS,
            "first_level_tests": len({r["test_name"] for r in first}),
            "first_level_values": len(first),
            "pass": sum(r["status"] == "pass" for r in first),
            "fail": sum(r["status"] == "fail" for r in first),
            "not_applicable": sum(r["status"] == "not-applicable" for r in first),
        })
    if not per_test:
        raise SystemExit("no category outputs found")
    write_csv(OUT / "nist_per_test_summary.csv", per_test)
    write_csv(OUT / "headline_counts.csv", headline)

    before = before_table_from_docx(Path("/home/ubuntu/upload/authenticated_tpe_latest_old_format.docx"))
    after_by_test = {}
    for row in per_test:
        if row["category"] == "hmac_drbg":
            after_by_test[row["test"]] = row
    comparison = []
    for test, entry in before.items():
        row = after_by_test.get(test)
        comparison.append({
            "test": test,
            "test_label": N.TEST_LABELS[test],
            "before_step2_intermediate_p": entry[BEFORE_COLUMNS[0]]["p_value"],
            "before_step2_intermediate_result": entry[BEFORE_COLUMNS[0]]["result"],
            "before_final_marked_p": entry[BEFORE_COLUMNS[1]]["p_value"],
            "before_final_marked_result": entry[BEFORE_COLUMNS[1]]["result"],
            "after_stream": "hmac_drbg (100 streams)" if row else "",
            "after_components": row["components"] if row else "",
            "after_uniformity_p_range": (
                f"{row['suite_uniformity_p_min']} .. {row['suite_uniformity_p_max']}") if row else "",
            "after_recomputed_p_range": (
                f"{row['recomputed_uniformity_p_min']} .. {row['recomputed_uniformity_p_max']}") if row else "",
            "after_pass": row["pass"] if row else "",
            "after_fail": row["fail"] if row else "",
            "after_not_applicable": row["not_applicable"] if row else "",
        })
    write_csv(OUT / "before_after.csv", comparison)
    print(f"wrote {OUT/'nist_per_test_summary.csv'} ({len(per_test)} rows), "
          f"{OUT/'headline_counts.csv'}, {OUT/'before_after.csv'}")


if __name__ == "__main__":
    main()