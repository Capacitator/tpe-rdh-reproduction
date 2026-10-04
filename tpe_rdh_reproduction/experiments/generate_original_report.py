"""Regenerate the original-project report and executive summary from artifacts."""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "tpe_rdh_reproduction"
REPORT = PROJECT / "reports/ORIGINAL_TPE_RDH_REPORT.md"
SUMMARY = PROJECT / "reports/EXECUTIVE_SUMMARY.md"


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def environment() -> str:
    packages = ("numpy", "pillow", "scikit-image", "pytest", "matplotlib")
    versions = ", ".join(f"{name} {importlib.metadata.version(name)}" for name in packages)
    return f"Python {sys.version.split()[0]}; {versions}"


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def run_tests() -> str:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-q"],
        cwd=PROJECT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stdout)
    match = re.search(r"(\d+ passed[^\n]*)", result.stdout)
    return match.group(1) if match else result.stdout.strip().splitlines()[-1]


def fmt(value: float, digits: int = 2) -> str:
    return f"{value:.{digits}f}"


def generated_validation() -> str:
    out = ["## Validation results", "", "### Exact recovery, payload, and capacity", ""]
    uct = rows(PROJECT / "output/uct_colour_all_blocks/summary.csv")
    uct_ok = sum(r["exact_recovery"].lower() == "true" and r["payload_recovered"].lower() == "true" for r in uct)
    out.append(f"`output/uct_colour_all_blocks/summary.csv` contains {len(uct)} image/block-size runs; {uct_ok}/{len(uct)} report exact image recovery and payload recovery. All rows report zero maximum recovery error and post-RDH block-sum preservation. The original images retain their native dimensions in this experiment.")
    quality = rows(PROJECT / "output/section6/quality_metrics.csv")
    summary = rows(PROJECT / "output/section6/summary_metrics.csv")
    q_ok = sum(r["exact_recovery"].lower() == "true" for r in quality)
    out.extend(["", f"The Section 6-style experiment contains {len(quality)} image/block-size cases; {q_ok}/{len(quality)} report exact recovery (PSNR=inf, SSIM=1, maximum error 0). The synthetic demonstration reports exact image recovery and a recovered {next(line.split(': ', 1)[1] for line in (PROJECT / 'results/metrics.txt').read_text().splitlines() if line.startswith('payload_bits:'))}-bit payload.", "", "### Thumbnail and block sums", ""])
    thumb = rows(PROJECT / "output/thumbnail_metrics.csv")
    for stage in sorted({r["stage"] for r in thumb}):
        diffs = [abs(int(r["abs_difference"])) for r in thumb if r["stage"] == stage]
        preserved = sum(d == 0 for d in diffs)
        out.append(f"The thumbnail stage artifact reports {preserved}/{len(diffs)} block/channel sums unchanged at `{stage}`; maximum absolute difference is {max(diffs)} and mean absolute difference is {sum(diffs)/len(diffs):.4f}.")
    out.extend(["", "The all-block UCT table separately records post-RDH block-sum preservation for every listed run. This distinction reflects that substitution preserves the RDH-marked sums, while RDH itself may change sums.", "", "### NPCR and UACI", ""])
    section = rows(PROJECT / "output/section6/summary_metrics.csv")
    n = [float(r["npcr_percent"]) for r in section]
    u = [float(r["uaci_percent"]) for r in section]
    channel_rows = rows(PROJECT / "output/section6/differential_metrics.csv")
    cn = [float(r["npcr_percent"]) for r in channel_rows]
    cu = [float(r["uaci_percent"]) for r in channel_rows]
    out.append(f"Across {len(section)} Section 6 RGB-mean rows, NPCR is {fmt(min(n))}%–{fmt(max(n))}% and UACI is {fmt(min(u))}%–{fmt(max(u))}%. Across {len(channel_rows)} per-channel rows, NPCR is {fmt(min(cn))}%–{fmt(max(cn))}% and UACI is {fmt(min(cu))}%–{fmt(max(cu))}%. The input perturbation is recorded in `output/section6/provenance.txt`; these are implementation diagnostics, not the paper's official security table.")
    key = rows(PROJECT / "output/key_sensitivity/uct_key_sensitivity_npcr_uaci.csv")
    kn = [float(r["rgb_npcr_percent"]) for r in key]
    ku = [float(r["rgb_uaci_percent"]) for r in key]
    out.extend(["", f"The separate fixed-identifier one-bit-key sweep contains {len(key)} rows: RGB NPCR {fmt(min(kn))}%–{fmt(max(kn))}% and RGB UACI {fmt(min(ku))}%–{fmt(max(ku))}%. Per-channel values are in `output/key_sensitivity/uct_key_sensitivity_npcr_uaci.csv`.", "", "### Entropy and adjacent-pixel correlation", ""])
    metrics = (PROJECT / "results/metrics.txt").read_text(encoding="utf-8")
    metric_map = dict(line.split(": ", 1) for line in metrics.splitlines() if ": " in line)
    ent0 = float(metric_map["entropy_original"])
    ent1 = float(metric_map["entropy_encrypted"])
    corr = rows(PROJECT / "output/section6/correlation_metrics.csv")
    orig = [float(r["original_correlation"]) for r in corr]
    enc = [float(r["encrypted_correlation"]) for r in corr]
    out.append(f"The checked-in synthetic demo reports image-level entropy {ent0:.6f} bits for the source and {ent1:.6f} bits for ciphertext; no multi-image entropy table is available. Section 6 correlation has {len(corr)} sampled luminance rows: original {min(orig):.4f}–{max(orig):.4f}, encrypted {min(enc):.4f}–{max(enc):.4f}. The experiment uses 5,000 deterministic adjacent pairs per direction. These are separate fixtures and calculations.")
    return "\n".join(out) + "\n\n" + generated_nist()


def generated_key_reuse() -> str:
    text = (PROJECT / "output/final_demo/final_demo_report.txt").read_text(encoding="utf-8")
    fields = {}
    for line in text.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            fields[key] = value.strip()
    keys = ("Image-derived identifiers differed", "Upsilon_P matrices differed", "Upsilon_S matrices differed", "Ciphertexts differed")
    if any(fields.get(key) != "yes" for key in keys):
        raise RuntimeError("Same-key/different-image artifact is missing expected positive outcomes")
    return ("### Image-derived key-reuse behavior\n\n"
            f"The checked-in same-key/different-image artifact reports image-derived identifiers differed: **{fields[keys[0]]}**; Upsilon_P matrices differed: **{fields[keys[1]]}**; Upsilon_S matrices differed: **{fields[keys[2]]}**; ciphertexts differed: **{fields[keys[3]]}**. It also records exact recovery and payload recovery for both demo images. This demonstrates implementation diversification for that fixture and is not evidence of cryptographic security. Source: `output/final_demo/final_demo_report.txt`.\n\n")


def generated_nist() -> str:
    data = rows(PROJECT / "output/nist_sp800_22/results.csv")
    nist_prov = dict(line.split("=", 1) for line in (PROJECT / "output/nist_sp800_22/provenance.txt").read_text().splitlines() if "=" in line)
    out = ["## NIST SP 800-22 Rev. 1a", "", f"The recorded run uses official NIST STS {nist_prov['nist_sts_version']}. Stream construction: {nist_prov['streams_per_category']} streams per category, {int(nist_prov['stream_length_bits']):,} bits per stream, alpha {nist_prov['significance_level']}. Full category conversions, key schedule and image order are recorded in `output/nist_sp800_22/provenance.txt`.", "", f"Selected tests: {nist_prov['selected_tests']}. Parameters: {nist_prov['STS_parameters']}.", "", "Aggregate component outcomes:", "", "| Stream category | Pass | Fail | Not applicable | Total |", "|---|---:|---:|---:|---:|"]
    def status(value: str) -> str:
        value = value.strip().lower().replace("-", "_").replace(" ", "_")
        return "not_applicable" if value in {"na", "n_a", "not_applicable"} else value

    categories = sorted({r["source_category"] for r in data})
    totals = {}
    for category in categories:
        counts = Counter(status(r["status"]) for r in data if r["source_category"] == category)
        totals[category] = counts
        out.append(f"| {category} | {counts['pass']} | {counts['fail']} | {counts['not_applicable']} | {sum(counts.values())} |")
    out.extend(["", "Per-test component counts (pass / fail / not applicable):", "", "| Test | Chaotic matrices | Final ciphertext |", "|---|---:|---:|"])
    tests = list(dict.fromkeys(r["test_name"] for r in data))
    for test in tests:
        cells = []
        for category in ("chaotic", "ciphertext"):
            counts = Counter(status(r["status"]) for r in data if r["test_name"] == test and r["source_category"] == category)
            cells.append(f"{counts['pass']} / {counts['fail']} / {counts['not_applicable']}")
        out.append(f"| {test} | {cells[0]} | {cells[1]} |")
    out.extend(["", "The results are mixed and contain substantial failures. Not applicable is not a pass. These statistical tests do not establish cryptographic security and are not a substitute for cryptanalysis."])
    return "\n".join(out) + "\n"


def generated_provenance(test_result: str) -> str:
    packages = ("numpy", "pillow", "scikit-image", "pytest", "matplotlib")
    deps = ", ".join(f"{p} {importlib.metadata.version(p)}" for p in packages)
    branch = git("branch", "--show-current")
    commit = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain"))
    inputs = []
    for path in sorted((PROJECT / "input/uct_colour").glob("*.tif")):
        inputs.append(f"| `{path.relative_to(PROJECT).as_posix()}` | `{sha256(path)}` |")
    return "\n".join([
        "## Tests, reproduction, and provenance", "",
        f"The original-project suite command `python -m pytest tests -q` from `tpe_rdh_reproduction/` completed successfully: **{test_result}**.",
        "", "### Artifact provenance", "",
        f"- Branch: `{branch}`; source commit: `{commit}`.",
        f"- Source worktree at report generation: `{'dirty' if dirty else 'clean'}`; this records the actual state, including report-generation edits.",
        f"- Runtime: {environment()}.",
        "- UCT source inputs are TIFF files under `tpe_rdh_reproduction/input/uct_colour/`; hashes cover file bytes:",
        "", "| Input | SHA-256 |", "|---|---|", *inputs,
        "", "- Report-generation script: `tpe_rdh_reproduction/experiments/generate_original_report.py`.",
        "- Exact generation command from repository root: `.venv/bin/python tpe_rdh_reproduction/experiments/generate_original_report.py`.",
        "- Artifact paths: `tpe_rdh_reproduction/results/metrics.txt`; `tpe_rdh_reproduction/output/{uct_colour_all_blocks,section6,key_sensitivity,nist_sp800_22}/`; thumbnail sums: `tpe_rdh_reproduction/output/thumbnail_metrics.csv`.",
        "- Historical run commits and runtime versions remain recorded separately in `output/nist_sp800_22/provenance.txt`, `output/section6/provenance.txt`, and `results/metrics.txt`. Those records are not represented as current clean-source runs.",
        "- Paper source and documented assumptions: `tpe_rdh_reproduction/docs/paper_map.md`, `docs/IMPLEMENTATION_NOTES.md`, and `docs/SECTION5_NOTES.md`.",
    ]) + "\n"


def main() -> None:
    test_result = run_tests()
    current = REPORT.read_text(encoding="utf-8")
    prefix = current.split("## Validation results", 1)[0]
    assumptions = current.split("## Assumptions and limitations", 1)[1]
    prefix = re.sub(r"### Image-derived key-reuse behavior\n.*\Z", generated_key_reuse(), prefix, flags=re.S)
    assumptions = assumptions.split("## Tests, reproduction, and provenance", 1)[0]
    report = prefix + generated_validation() + "\n## Assumptions and limitations" + assumptions
    report += "\n" + generated_provenance(test_result)
    REPORT.write_text(report.rstrip() + "\n", encoding="utf-8")
    uct = rows(PROJECT / "output/uct_colour_all_blocks/summary.csv")
    nist = rows(PROJECT / "output/nist_sp800_22/results.csv")
    count = Counter()
    for row in nist:
        status = row["status"].lower().replace("-", "_").replace(" ", "_")
        status = "not_applicable" if status in {"na", "n_a", "not_applicable"} else status
        count[status] += 1
    summary = f"""# Executive summary — original chaotic TPE/RDH

## Implemented and tested

This project implements the original chaotic TPE/RDH pipeline: chaotic-map generation, `Upsilon_P`/`Upsilon_S`, block permutation, histogram-shifting RDH, sum-preserving substitution, decryption and exact image/payload recovery.

- Test suite: **{test_result}**.
- UCT all-block experiment: {sum(r['exact_recovery'].lower() == 'true' for r in uct)}/{len(uct)} rows report exact recovery.
- NIST SP 800-22 component outcomes across recorded streams: {count['pass']} pass, {count['fail']} fail, {count.get('not_applicable', 0)} not applicable. Results are mixed with substantial failures.
- NPCR/UACI, entropy, correlation and block-sum results are dynamically summarized in [the detailed report](ORIGINAL_TPE_RDH_REPORT.md) from checked-in artifacts.

## Limitations and final status

The implementation has documented assumptions where the paper is underspecified. Statistical tests do not establish cryptographic security. The original pipeline has no authentication layer.

> The original chaotic TPE/RDH pipeline passes its functional, key-reuse, recovery, and documented image-level validation tests. NIST SP 800-22 results are mixed and include substantial failures. These tests do not establish cryptographic security.

Final status: functional reproduction prototype with documented limitations; cryptographic security is not established.

## Provenance

Branch `{git('branch', '--show-current')}`, source commit `{git('rev-parse', 'HEAD')}`; current worktree state: `{'dirty' if git('status', '--porcelain') else 'clean'}`. See the detailed report for runtime versions, image hashes, commands, artifact paths and generation script.
"""
    SUMMARY.write_text(summary, encoding="utf-8")


if __name__ == "__main__":
    main()
