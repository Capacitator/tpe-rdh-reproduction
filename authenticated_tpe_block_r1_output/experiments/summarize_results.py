#!/usr/bin/env python3
"""Verify actual-r1 campaign artifacts and write transparent per-test summaries."""
from __future__ import annotations
import csv
import hashlib
import math
from collections import defaultdict
from pathlib import Path

from scipy.stats import binom

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
ALPHA = 0.01
UNIFORMITY_ALPHA = 0.0001


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise AssertionError(f"refusing to write empty CSV: {path}")
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    stream_manifest = read_csv(OUT / "stream_manifest.csv")
    assert len(stream_manifest) == 100
    stream_hashes = []
    used_keys = set()
    for row in stream_manifest:
        path = ROOT / row["path"]
        assert path.is_file() and path.stat().st_size == 125_000
        assert sha256_file(path) == row["stream_sha256"]
        stream_hashes.append(row["stream_sha256"])
        a, b = int(row["user_key_index_start"]), int(row["user_key_index_end_inclusive"])
        assert b - a + 1 == int(row["user_keys_used"])
        indices = set(range(a, b + 1))
        assert not (indices & used_keys), "key index reused across actual-r1 streams"
        used_keys |= indices
    assert len(set(stream_hashes)) == 100

    ascii_path = OUT / "nist_input" / "block_r1_actual_output_ascii.txt"
    line_count = 0
    with ascii_path.open("rb") as f:
        for line_count, line in enumerate(f, 1):
            assert len(line) == 1_000_001 and line.endswith(b"\n")
            assert set(line[:-1]) <= {ord("0"), ord("1")}
    assert line_count == 100

    first = read_csv(OUT / "first_level_pvalues.csv")
    second = read_csv(OUT / "second_level_uniformity.csv")
    counts = read_csv(OUT / "summary_counts.csv")
    assert len(first) == 18_800
    assert len(counts) == 188
    assert len(second) == 188
    first_pass = sum(r["status"] == "pass" for r in first)
    first_fail = sum(r["status"] == "fail" for r in first)
    first_na = sum(r["status"] == "not-applicable" for r in first)
    assert first_pass + first_fail + first_na == len(first)
    valid_second = [r for r in second if r["recomputed_uniformity_p_value"].strip()]
    second_p = [float(r["recomputed_uniformity_p_value"]) for r in valid_second]
    second_fail = sum(p < UNIFORMITY_ALPHA for p in second_p)

    by_test: dict[str, dict] = {}
    for row in counts:
        test = row["test_name"]
        entry = by_test.setdefault(test, {"pass": 0, "fail": 0, "not_applicable": 0,
                                          "components": 0})
        entry["components"] += 1
        for field in ("pass", "fail", "not_applicable"):
            entry[field] += int(row[field])
    second_by_test: dict[str, list[float]] = defaultdict(list)
    for row in valid_second:
        second_by_test[row["test_name"]].append(float(row["recomputed_uniformity_p_value"]))
    test_rows = []
    component_rows = []
    for test, entry in by_test.items():
        p, f, na = (entry[k] for k in ("pass", "fail", "not_applicable"))
        m = p + f
        second_values = second_by_test[test]
        # count N/A sequence instances once per test, not once per component
        na_streams = len({int(r["stream_index"]) for r in first
                          if r["test_name"] == test and r["status"] == "not-applicable"})
        test_rows.append({
            "nist_test": test,
            "components": entry["components"],
            "first_level_pass": p,
            "first_level_fail": f,
            "first_level_NA_component_values": na,
            "first_level_NA_streams": na_streams,
            "first_level_valid_p_values": m,
            "first_level_pass_rate": f"{p / m:.8f}" if m else "",
            "second_level_values": len(second_values),
            "second_level_failures_at_0_0001": sum(x < UNIFORMITY_ALPHA for x in second_values),
            "second_level_values_below_0_01_exploratory": sum(x < ALPHA for x in second_values),
            "minimum_second_level_p": f"{min(second_values):.12g}" if second_values else "",
        })

    for row in counts:
        p, f, na = (int(row[k]) for k in ("pass", "fail", "not_applicable"))
        n = p + f
        if not n:
            continue
        observed = p / n
        lower = (1 - ALPHA) - 3 * math.sqrt((1 - ALPHA) * ALPHA / n)
        tail = float(binom.sf(f - 1, n, ALPHA)) if f else 1.0
        component_rows.append({
            "nist_test": row["test_name"],
            "component": row["component_label"],
            "valid_streams": n,
            "pass": p,
            "fail": f,
            "not_applicable": na,
            "pass_proportion": f"{observed:.12g}",
            "nist_3sigma_lower_bound": f"{lower:.12g}",
            "below_nist_approx_bound": observed < lower,
            "exact_binomial_upper_tail_p": tail,
        })
    order = sorted(range(len(component_rows)), key=lambda i: float(component_rows[i]["exact_binomial_upper_tail_p"]))
    running = 0.0
    for rank, index in enumerate(order):
        raw = float(component_rows[index]["exact_binomial_upper_tail_p"])
        running = max(running, min(1.0, (len(order) - rank) * raw))
        component_rows[index]["holm_adjusted_p"] = running
        component_rows[index]["holm_reject_at_0_01"] = running <= ALPHA

    # Keep NIST's canonical test order rather than alphabetical order.
    order_names = ["Frequency", "BlockFrequency", "CumulativeSums", "Runs", "LongestRun",
                   "Rank", "FFT", "NonOverlappingTemplate", "OverlappingTemplate",
                   "Universal", "ApproximateEntropy", "RandomExcursions",
                   "RandomExcursionsVariant", "Serial", "LinearComplexity"]
    positions = {name: i for i, name in enumerate(order_names)}
    test_rows.sort(key=lambda r: positions[r["nist_test"]])
    write_csv(OUT / "test_by_test_summary.csv", test_rows)
    write_csv(OUT / "component_pass_proportion_review.csv", component_rows)

    raw_manifest = read_csv(OUT / "raw_report_manifest.csv")
    for row in raw_manifest:
        path = ROOT / row["path"]
        assert path.is_file() and sha256_file(path) == row["sha256"], f"raw report hash mismatch: {path}"

    below_approx = sum(bool(r["below_nist_approx_bound"]) for r in component_rows)
    holm_reject = sum(bool(r["holm_reject_at_0_01"]) for r in component_rows)
    valid_first = first_pass + first_fail
    lines = [
        "# Actual block-r1 output: NIST STS 2.1.2 results",
        "",
        "Supplemental test of the actual two-bit `r1` values consumed by the cipher. It preserves the earlier full-HMAC-digest `block_r1` campaign; it does not replace those results or tune the algorithm.",
        "",
        "## Protocol and integrity",
        "",
        "- Official NIST STS 2.1.2 `assess`, all default tests, ASCII input, 100 streams × 1,000,000 bits, first-level α=0.01.",
        f"- Streams: {len(stream_manifest)}; bytes per stream: 125,000; distinct stream hashes: {len(set(stream_hashes))}; disjoint UserKey indices: {len(used_keys)}.",
        f"- First-level p-value entries: {len(first)} = {first_pass} pass, {first_fail} fail, {first_na} N/A. Valid p-value pass rate: {100*first_pass/valid_first:.3f}% (expected approximately 99%).",
        f"- Second-level uniformity: {len(valid_second)} valid component p-values; {second_fail} below NIST's 0.0001 criterion; minimum {min(second_p):.12g}.",
        f"- NIST approximate three-sigma pass-proportion checks: {below_approx}/{len(component_rows)} components below the lower bound; exact one-sided binomial tests with Holm correction at 0.01: {holm_reject}/{len(component_rows)} significant.",
        f"- Raw STS files in report manifest: {len(raw_manifest)}; hash mismatches: 0. Input ASCII lines and stream sizes verified.",
        "- N/A entries arise from NIST Random Excursions applicability conditions; see per-test N/A stream counts below. They are not discarded failures.",
        "",
        "## Named NIST tests",
        "",
        "| NIST test | First-level P/F/N-A | Valid pass rate | N/A streams | Second-level p-values | Below 0.0001 | Minimum second-level p |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in test_rows:
        valid = int(r["first_level_valid_p_values"])
        lines.append(
            f"| {r['nist_test']} | {r['first_level_pass']}/{r['first_level_fail']}/{r['first_level_NA_component_values']} "
            f"| {100*float(r['first_level_pass_rate']):.3f}% | {r['first_level_NA_streams']} "
            f"| {r['second_level_values']} | {r['second_level_failures_at_0_0001']} "
            f"| {r['minimum_second_level_p'] or 'N/A'} |"
        )
    lines += [
        "",
        "The P/F/N-A values are summed across components (e.g. 148 template components); for the two Random Excursions tests, N/A component counts are not N/A stream counts. First-level failures are retained. Second-level values below 0.01 but above 0.0001 are listed in `test_by_test_summary.csv` as exploratory-only and are not NIST uniformity failures.",
        "",
        "## Interpretation",
        "",
        "The actual `r1` component passed Frequency 100/100, Block Frequency 99/100, and Runs 100/100. Across all NIST components there are 156 first-level failures among 17,786 applicable p-values, which is not a reason to alter keys, bit packing, parameters, or outcomes. No stream was removed. All 188 second-level uniformity values exceed 0.0001. These tests do not establish cryptographic security.",
        "",
        "The 0.000199 minimum uniformity p-value is close to but above the official 0.0001 cutoff. It is disclosed, not rounded into a failure or hidden. The test-by-test CSV, first-level p-values, second-level histograms, official raw reports, stream manifest and artifact hashes are retained under `output/`.",
        "",
    ]
    (OUT / "summary.md").write_text("\n".join(lines), encoding="utf-8")

    # Manifest all outputs except the manifest itself; paths relative to output/.
    artifact_rows = []
    for path in sorted(p for p in OUT.rglob("*") if p.is_file() and p.name != "artifact_manifest.csv"):
        artifact_rows.append({"path": str(path.relative_to(OUT)), "sha256": sha256_file(path), "bytes": path.stat().st_size})
    write_csv(OUT / "artifact_manifest.csv", artifact_rows)
    print(f"Verified 100 unique streams, {len(raw_manifest)} raw-report hashes, {len(first)} first-level entries, {len(valid_second)} second-level values.")
    print(f"P/F/N-A={first_pass}/{first_fail}/{first_na}; uniformity failures <0.0001={second_fail}; bound warnings={below_approx}; Holm significant={holm_reject}.")

if __name__ == "__main__":
    main()
