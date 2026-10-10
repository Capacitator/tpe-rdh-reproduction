#!/usr/bin/env python3
"""Run the corrected NIST SP 800-22 protocol over predefined stream families.

Usage:
    python experiments/run_protocol.py --sts-dir <NIST_STS_2_1_2_ROOT> [--parallel 4]
                                       [--categories a,b,c] [--skip-run]

Everything the experiment consumes is written under ``output/`` together with
SHA-256 manifests, so the whole campaign is reproducible and auditable.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime
import hashlib
import importlib.metadata
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
REPO = ROOT.parent

import streams as S  # noqa: E402
import nist_runner as N  # noqa: E402

OUT = ROOT / "output"
STS_WORK_ROOT = Path("/home/ubuntu/work/sts_runs")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        # Categories record category-specific detail fields, so take the union
        # in first-appearance order (missing cells are written empty).
        fieldnames = []
        for row in rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

def tree_copy(sts_root: Path, index: int) -> Path:
    """A private working copy of the built suite, so categories can run in parallel."""
    target = STS_WORK_ROOT / f"run{index}"
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(sts_root, target)
    return target


def generate_streams(workers: int) -> tuple[list[dict], dict]:
    all_rows: list[dict] = []
    for category in S.CATEGORY_ORDER:
        records = S.build_category(category, workers=workers)
        rows = S.write_category(records, OUT)
        all_rows.extend(rows)
        print(f"[streams] {category}: {len(rows)} streams written", flush=True)
    checks = S.check_no_repeats(all_rows)
    checks["key_partition"] = S.key_partition_report()
    checks["image_reuse"] = S.check_image_reuse(all_rows)
    checks["revision"] = S.v2.activation_status()
    return all_rows, checks


def run_one_category(sts_root: Path, tree: Path, category: str,
                     manifest_rows: list[dict]) -> dict:
    ascii_path = OUT / "nist_input" / f"{category}_ascii.txt"
    ascii_path.parent.mkdir(parents=True, exist_ok=True)
    category_rows = sorted([r for r in manifest_rows if r["category"] == category],
                           key=lambda r: r["stream_index"])
    with ascii_path.open("w", encoding="ascii") as handle:
        for row in category_rows:
            # stream_file is stored relative to the revision folder, not to output/
            payload = (ROOT / row["stream_file"]).read_bytes()
            handle.write(S.stream_ascii(payload))
            handle.write("\n")
    N.clean_results(tree)
    log_path = OUT / "nist_logs" / f"{category}_assess_stdout.txt"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    N.run_assess(tree, ascii_path, S.STREAM_COUNT, S.STREAM_BITS, log_path)
    collected = N.collect_reports(tree, OUT, category)
    first_level, warnings = N.parse_first_level(collected["raw_dir"], S.STREAM_COUNT)
    second_level = N.parse_second_level(collected["report"])
    summary = N.summarise(first_level, S.ALPHA)
    return {"category": category, "ascii_path": ascii_path, "ascii_sha256": sha256_file(ascii_path),
            "log": log_path, "raw_dir": collected["raw_dir"], "report": collected["report"],
            "first_level": first_level, "second_level": second_level, "summary": summary,
            "warnings": warnings, "tree": tree}


def write_category_outputs(result: dict) -> dict:
    category = result["category"]
    out_dir = OUT / "categories" / category
    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "first_level_pvalues.csv", [
        {"test_name": r["test_name"], "test_label": r["test_label"],
         "stream_index": r["stream_index"], "test_component": r["test_component"],
         "component_label": r["component_label"],
         "p_value": "" if r["p_value"] is None else f"{r['p_value']:.12g}",
         "status": "not-applicable" if r["p_value"] is None
                   else ("pass" if r["p_value"] >= S.ALPHA else "fail"),
         "significance_level": S.ALPHA}
        for r in result["first_level"]])
    write_csv(out_dir / "second_level_uniformity.csv", [
        {"test_name": r["test"], "test_label": N.TEST_LABELS.get(r["test"], r["test"]),
         "component": r.get("recomputed_component", ""),
         **{f"C{i + 1}": r["bins"][i] for i in range(10)},
         "suite_p_value": r["report_p_value"], "suite_pass_proportion": r["report_proportion"],
         "recomputed_chi_square": "" if r["chi_square"] is None else f"{r['chi_square']:.12g}",
         "recomputed_uniformity_p_value":
             "" if r["uniformity_p_value"] is None else f"{r['uniformity_p_value']:.12g}"}
        for r in result["second_level"]])
    write_csv(out_dir / "summary_counts.csv", result["summary"])
    raw_hashes = sorted(
        ({"path": str(p.relative_to(ROOT)), "sha256": sha256_file(p)}
         for p in sorted(result["raw_dir"].rglob("*")) if p.is_file()),
        key=lambda item: item["path"])
    write_csv(out_dir / "raw_report_manifest.csv", raw_hashes)
    (out_dir / "parse_warnings.txt").write_text(
        ("\n".join(result["warnings"]) + "\n") if result["warnings"] else "none\n",
        encoding="utf-8")
    return out_dir


def provenance(sts_root: Path, sts_patch: Path) -> list[str]:
    commit = subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"],
                                     text=True).strip()
    status = subprocess.check_output(["git", "-C", str(REPO), "status", "--porcelain"],
                                     text=True)
    versions = []
    for dist in ("numpy", "pillow", "scipy", "scikit-image", "pytest"):
        try:
            versions.append(f"{dist}={importlib.metadata.version(dist)}")
        except importlib.metadata.PackageNotFoundError:
            versions.append(f"{dist}=not-installed")
    return [
        f"generated_utc={datetime.datetime.now(datetime.timezone.utc).isoformat()}",
        f"repository_commit={commit}",
        f"worktree={'clean' if not status.strip() else 'modified'}",
        f"revision_id={S.v2.REVISION_ID}",
        f"revision_summary={S.v2.REVISION_SUMMARY}",
        f"protocol_script_sha256={sha256_file(Path(__file__))}",
        f"streams_module_sha256={sha256_file(ROOT / 'src' / 'streams.py')}",
        f"atpe_v2_module_sha256={sha256_file(ROOT / 'src' / 'atpe_v2.py')}",
        f"nist_runner_module_sha256={sha256_file(ROOT / 'src' / 'nist_runner.py')}",
        f"python={platform.python_version()}",
        *versions,
        "nist_sts_version=2.1.2",
        "nist_sts_source=https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip",
        f"nist_sts_build_patch={sts_patch}",
        f"nist_sts_build_patch_sha256={sha256_file(sts_patch)}",
        f"sts_binary_sha256={sha256_file(sts_root / 'assess')}",
        "sts_command=assess 1000000 with answers '0 <ascii_path> 1 0 100 0' "
        "(input-file generator, all tests, default parameters, 100 streams, ASCII mode)",
        f"streams_per_category={S.STREAM_COUNT}",
        f"bits_per_stream={S.STREAM_BITS}",
        f"significance_level={S.ALPHA}",
        f"categories={','.join(S.CATEGORY_ORDER)}",
        f"category_kinds={json.dumps(S.CATEGORY_KIND, sort_keys=True)}",
        f"key_index_partition={json.dumps(S.KEY_RANGES, sort_keys=True)}",
        f"image_pool_size={S.STREAM_COUNT + len(S.UCT_NAMES)}",
        "image_pool=6 UCT colour images (tpe_rdh_reproduction/input/uct_colour) "
        "+ 100 distinct UCID images (github.com/girfa/ColorImageDatasets, UCID-1338/1..100.tif), "
        "each converted to RGB and resized once to 512x512 with PIL LANCZOS",
        "bit_order=MSB-first within each byte, bytes in row-major order, first 1,000,000 bits of "
        "the 125,000-byte stream payload",
        "evaluation=official assess executable; first-level p-values from the suite's per-test "
        "results.txt; second-level uniformity recomputed from the suite's C1..C10 histogram with "
        "gammaincc(9/2, chi2/2) and cross-checked against the suite's printed value",
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sts-dir", type=Path, required=True)
    parser.add_argument("--parallel", type=int, default=4)
    parser.add_argument("--categories", default=",".join(S.CATEGORY_ORDER))
    parser.add_argument("--skip-run", action="store_true",
                        help="reuse existing streams and only re-run the suite")
    parser.add_argument("--metrics", action="store_true", default=True)
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    pool_meta = S.ensure_image_cache()
    write_csv(OUT / "image_pool_manifest.csv", pool_meta)
    print(f"[pool] {len(pool_meta)} distinct normalized images", flush=True)

    manifest_path = OUT / "stream_manifest.csv"
    if args.skip_run and manifest_path.is_file():
        import csv as _csv
        with manifest_path.open(newline="", encoding="utf-8") as handle:
            manifest_rows = list(_csv.DictReader(handle))
        checks = json.loads((OUT / "independence_checks.json").read_text())
    else:
        manifest_rows, checks = generate_streams(workers=min(args.parallel, 6))
        write_csv(manifest_path, manifest_rows)
        (OUT / "independence_checks.json").write_text(json.dumps(checks, indent=2) + "\n")

    categories = [c for c in args.categories.split(",") if c]
    results = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.parallel) as executor:
        futures = {}
        for index, category in enumerate(categories):
            tree = tree_copy(args.sts_dir, index)
            futures[executor.submit(run_one_category, args.sts_dir, tree, category,
                                    manifest_rows)] = category
        for future in concurrent.futures.as_completed(futures):
            category = futures[future]
            result = future.result()
            out_dir = write_category_outputs(result)
            print(f"[nist] {category}: parsed -> {out_dir.relative_to(ROOT)} "
                  f"({len(result['first_level'])} first-level values, "
                  f"{len(result['warnings'])} parse warnings)", flush=True)
            results.append(result)

    sts_patch = Path("/home/ubuntu/work/sts/sts_build.patch")
    if sts_patch.is_file():
        (OUT / "provenance.txt").write_text(
            "\n".join(provenance(args.sts_dir, sts_patch)) + "\n", encoding="utf-8")
    with (OUT / "protocol_summary.json").open("w", encoding="utf-8") as handle:
        json.dump({"independence": checks,
                   "categories": {r["category"]: {
                       "first_level_values": len(r["first_level"]),
                       "parse_warnings": r["warnings"],
                       "ascii_sha256": r["ascii_sha256"],
                       "report_sha256": sha256_file(r["report"]),
                       "counts": {k: sum(1 for s in r["summary"] for _ in range(s[k]))
                                  for k in ("pass", "fail", "not_applicable")}}
                   for r in results}}, handle, indent=2)
    print("[done]", flush=True)


if __name__ == "__main__":
    main()
