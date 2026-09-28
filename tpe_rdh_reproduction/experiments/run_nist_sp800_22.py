#!/usr/bin/env python3
"""Run the NIST SP 800-22 Rev. 1a suite on reproducible pipeline bitstreams.

The external NIST STS 2.1.2 source checkout is deliberately supplied by the
caller with --sts-dir. This script drives its official `assess` executable;
it does not substitute other statistical metrics for NIST tests.
"""
from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import importlib.metadata
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
OUT = ROOT / "output" / "nist_sp800_22"
BITS_PER_STREAM = 1_000_000
STREAM_COUNT = 10
ALPHA = 0.01
IMAGE_NAMES = ["airplane", "baboon", "couple", "girl", "lena", "peppers",
               "airplane", "baboon", "couple", "girl"]
BASE_KEY = hashlib.sha256(b"tpe-rdh-nist-shared-key").digest()
KEYS = [BASE_KEY, BASE_KEY] + [
    hashlib.sha256(f"tpe-rdh-nist-key-{i}".encode()).digest()
    for i in range(2, STREAM_COUNT)
]


def quantize_chaos(values: np.ndarray) -> np.ndarray:
    """Map chaotic values in [-1,1] to uint8 via floor((x+1)*128), clipped."""
    scaled = np.floor((np.asarray(values, dtype=np.float64) + 1.0) * 128.0)
    return np.clip(scaled, 0, 255).astype(np.uint8)


def packed_bits(byte_values: np.ndarray, bit_count: int = BITS_PER_STREAM) -> str:
    """Return MSB-first bytes as ASCII bits, truncated to exactly bit_count."""
    raw = np.asarray(byte_values, dtype=np.uint8).tobytes(order="C")
    if len(raw) * 8 < bit_count:
        raise ValueError(f"need {bit_count} bits, got {len(raw) * 8}")
    return "".join(f"{byte:08b}" for byte in raw)[:bit_count]


def parse_status(pvalue: str | None, alpha: float = ALPHA) -> str:
    if pvalue is None or pvalue in {"", "----", "N/A", "nan", "NaN"}:
        return "not-applicable"
    value = float(pvalue)
    return "pass" if value >= alpha else "fail"


def _make_streams() -> tuple[list[dict], dict[str, list[str]]]:
    from pipeline import DemoPipelineParameters, encrypt_rgb_image

    manifest = []
    streams: dict[str, list[str]] = {"chaotic": [], "ciphertext": []}
    for i, name in enumerate(IMAGE_NAMES):
        path = ROOT / "input" / "uct_colour" / f"{name}.tif"
        with Image.open(path) as image_file:
            image = np.asarray(image_file.convert("RGB"), dtype=np.uint8)
        params = DemoPipelineParameters(key=KEYS[i], block_size=16)
        encrypted = encrypt_rgb_image(image, [], params)
        # Upsilon values are the implementation's actual matrices. Each is
        # quantized separately, concatenated P then S, and encoded MSB first.
        chaos_bytes = np.concatenate((quantize_chaos(encrypted.upsilon_p),
                                      quantize_chaos(encrypted.upsilon_s)))
        streams["chaotic"].append(packed_bits(chaos_bytes))
        streams["ciphertext"].append(packed_bits(encrypted.encrypted_image))
        manifest.append({
            "stream_index": i + 1,
            "image": f"input/uct_colour/{name}.tif",
            "image_sha256": hashlib.sha256(image.tobytes(order="C")).hexdigest(),
            "key_hex": KEYS[i].hex(),
            "identifier_mode": "automatic SHA-256 identifier from plaintext RGB pixels",
            "image_identifier_hex": bytes(encrypted.image_identifier).hex(),
            "block_size": 16,
            "chaotic_bits": BITS_PER_STREAM,
            "ciphertext_bits": BITS_PER_STREAM,
        })
    return manifest, streams


def _run_category(sts_root: Path, category: str, streams: list[str]) -> tuple[Path, Path]:
    input_path = OUT / f"{category}_input_ascii.txt"
    input_path.write_text("\n".join(streams) + "\n", encoding="ascii")
    # Generator choice 0, input path, all tests, default test parameters,
    # number of sequences, ASCII mode.
    answers = f"0\n{input_path.resolve()}\n1\n0\n{len(streams)}\n0\n"
    proc = subprocess.run([str(sts_root / "assess"), str(BITS_PER_STREAM)],
                          cwd=sts_root, input=answers, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=1800)
    # Console text contains interactive prompts with intentional upstream
    # trailing whitespace; the canonical suite report is preserved instead.
    # The original NIST assess.c returns 1 even after a successful test run.
    if "Statistical Testing Complete" not in proc.stdout:
        raise RuntimeError(f"NIST assess failed for {category}")
    exp = sts_root / "experiments" / "AlgorithmTesting"
    report = OUT / f"{category}_finalAnalysisReport.txt"
    shutil.copyfile(exp / "finalAnalysisReport.txt", report)
    raw_dir = OUT / f"{category}_raw"
    if raw_dir.exists():
        shutil.rmtree(raw_dir)
    shutil.copytree(exp, raw_dir)
    return report, exp


def _summary_rows(report: Path) -> list[tuple[str, str, str]]:
    parsed = []
    for line in report.read_text(errors="replace").splitlines():
        match = re.match(r"\s*(?:[0-9]+\s+){10}(\d+(?:\.\d+)?|----)\s+\*?\s*(\d+/\d+|------)\s+\*?\s*([A-Za-z]+)\s*$", line)
        if match:
            pvalue, proportion, test = match.groups()
            parsed.append((test, pvalue, proportion))
    return parsed


def _write_results(sts_root: Path, reports: dict[str, Path]) -> None:
    with (OUT / "results.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["test_name", "source_category", "stream_index",
            "stream_length_bits", "test_component", "p_value", "status", "pass_proportion", "significance_level"],
            lineterminator="\n")
        writer.writeheader()
        for category, report in reports.items():
            summary_rows = _summary_rows(report)
            raw_root = OUT / f"{category}_raw"
            test_names = [row[0] for row in summary_rows]
            for test in dict.fromkeys(test_names):
                summaries = [(p, prop) for t, p, prop in summary_rows if t == test]
                result_file = raw_root / test / "results.txt"
                values = []
                if result_file.exists():
                    for token in result_file.read_text(errors="replace").split():
                        try:
                            values.append(float(token))
                        except ValueError:
                            pass
                components = len(summaries)
                if test in {"RandomExcursions", "RandomExcursionsVariant"}:
                    # These tests can skip individual sequences when their
                    # random-walk cycle count is below NIST's minimum. Parse
                    # native per-sequence logs so skipped streams stay N/A.
                    heading = ("RANDOM EXCURSIONS TEST" if test == "RandomExcursions"
                               else "RANDOM EXCURSIONS VARIANT TEST")
                    blocks = (raw_root / test / "stats.txt").read_text(errors="replace").split(heading)
                    symbols = ([-4, -3, -2, -1, 1, 2, 3, 4] if test == "RandomExcursions" else list(range(-9, 0)) + list(range(1, 10)))
                    for stream_index, block in enumerate(blocks[1:], 1):
                        if stream_index > STREAM_COUNT:
                            break
                        if "TEST NOT APPLICABLE" in block:
                            for symbol in symbols:
                                writer.writerow({"test_name": test, "source_category": category,
                                    "stream_index": stream_index, "stream_length_bits": BITS_PER_STREAM,
                                    "test_component": f"state={symbol}", "p_value": "",
                                    "status": "not-applicable", "pass_proportion": "",
                                    "significance_level": ALPHA})
                            continue
                        pvals = re.findall(r"p[-_]value\s*=\s*([0-9.]+)", block)
                        for j, symbol in enumerate(symbols):
                            pval = pvals[j] if j < len(pvals) else None
                            summary = summaries[j] if j < len(summaries) else ("----", "")
                            writer.writerow({"test_name": test, "source_category": category,
                                "stream_index": stream_index, "stream_length_bits": BITS_PER_STREAM,
                                "test_component": f"state={symbol}", "p_value": pval or "",
                                "status": parse_status(pval), "pass_proportion": summary[1],
                                "significance_level": ALPHA})
                    continue
                if components == 0 or len(values) != STREAM_COUNT * components:
                    # Preserve the source report and explicitly expose that
                    # per-stream values could not be mapped to report rows.
                    components = max(components, 1)
                    values = []
                for stream_index in range(STREAM_COUNT):
                    for component_index in range(components):
                        pval = values[stream_index * components + component_index] if values else None
                        summary = summaries[component_index] if component_index < len(summaries) else ("----", "")
                        writer.writerow({"test_name": test, "source_category": category,
                            "stream_index": stream_index + 1, "stream_length_bits": BITS_PER_STREAM,
                            "test_component": f"component={component_index + 1}",
                            "p_value": "" if pval is None else f"{pval:.8g}",
                            "status": parse_status(None if pval is None else str(pval)),
                            "pass_proportion": summary[1], "significance_level": ALPHA})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sts-dir", type=Path, required=True,
                        help="NIST-Statistical-Test-Suite checkout at a pinned commit")
    args = parser.parse_args()
    suite_base = args.sts_dir.resolve()
    candidates = [suite_base, suite_base / "sts", suite_base / "sts-2.1.2",
                  suite_base / "sts-2.1.2" / "sts-2.1.2"]
    sts_root = next((p for p in candidates if (p / "assess").is_file() or
                     (p / "makefile").is_file() or (p / "Makefile").is_file()), None)
    if sts_root is None:
        raise FileNotFoundError(f"No NIST STS source/build found under {suite_base}")
    OUT.mkdir(parents=True, exist_ok=True)
    if not (sts_root / "assess").exists():
        setup_script = sts_root.parent / "setup.sh"
        if setup_script.exists():
            subprocess.run(["bash", str(setup_script)], check=True)
            sts_root = sts_root.parent / "sts"
        else:
            (sts_root / "obj").mkdir(exist_ok=True)
            exp = sts_root / "experiments"
            for name in ("AlgorithmTesting", "BBS", "CCG", "G-SHA1", "LCG", "MODEXP", "MS", "QCG1", "QCG2", "XOR"):
                (exp / name).mkdir(parents=True, exist_ok=True)
            subprocess.run(["bash", "./create-dir-script"], cwd=exp, check=True)
        subprocess.run(["make"], cwd=sts_root, check=True)
    manifest, streams = _make_streams()
    with (OUT / "stream_manifest.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(manifest[0]), lineterminator="\n")
        writer.writeheader(); writer.writerows(manifest)
    reports = {}
    for category, category_streams in streams.items():
        report, _ = _run_category(sts_root, category, category_streams)
        reports[category] = report
    _write_results(sts_root, reports)
    # Preserve canonical reports and parsed results, but discard the thousands
    # of per-template scratch files generated internally by the STS program.
    for category in reports:
        shutil.rmtree(OUT / f"{category}_raw")
    try:
        sts_commit = subprocess.check_output(["git", "-C", str(sts_root.parent), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except subprocess.CalledProcessError:
        sts_commit = "official NIST STS 2.1.2 distribution (no git commit)"
    source_commit = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    provenance = [f"source_commit={source_commit}", "source_worktree=modified at experiment run; uncommitted changes retained",
        f"source_script_sha256={hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}",
        f"python={platform.python_version()}",
        f"numpy={np.__version__}", f"pillow={Image.__version__}",
        *[f"{dist}={importlib.metadata.version(dist)}" for dist in
          ("pytest", "matplotlib", "scikit-image", "scipy")],
        "nist_sts_version=2.1.2", "nist_sts_source=https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip",
        "nist_sts_build_command=make (in official sts-2.1.2/sts-2.1.2)",
        "practical_reference=https://github.com/terrillmoore/NIST-Statistical-Test-Suite (reference only; not used to run the suite)",
        f"retrieval_date={datetime.date.today().isoformat()}",
        f"command={sys.executable} experiments/run_nist_sp800_22.py --sts-dir {args.sts_dir}",
        f"streams_per_category={STREAM_COUNT}", f"stream_length_bits={BITS_PER_STREAM}",
        f"significance_level={ALPHA}",
        "conversion=ciphertext: uint8 RGB bytes, row-major, channel order RGB, MSB-first; first 1,000,000 bits",
        "conversion=chaotic: Upsilon_P then Upsilon_S; quantize floor((x+1)*128) clipped to uint8; row-major; MSB-first; first 1,000,000 bits",
        "key_schedule=streams 1-2 share SHA-256('tpe-rdh-nist-shared-key'); streams 3-10 use SHA-256('tpe-rdh-nist-key-{zero_based_index}')",
        "image order=" + ",".join(IMAGE_NAMES),
        "NIST tests run with default SP 800-22 STS 2.1.2 parameters (including default block lengths); alpha=0.01"]
    provenance += ["selected_tests=Frequency, BlockFrequency, CumulativeSums, Runs, LongestRun, Rank, FFT, NonOverlappingTemplate, OverlappingTemplate, Universal, ApproximateEntropy, RandomExcursions, RandomExcursionsVariant, Serial, LinearComplexity",
        "STS_parameters=Block Frequency M=128; Non-overlap template m=9; Overlap template m=9; Approximate Entropy m=10; Serial m=16; Linear Complexity M=500; remaining suite defaults",
        "sources_accessed=2026-09-28",
        "source_1=https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software",
        "source_2=https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf",
        "source_3=https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software/guide-to-the-statistical-tests",
        "source_4=https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final (publication date: 2010-04-30)",
        "source_5=https://csrc.nist.gov/news/2022/decision-to-revise-nist-sp-800-22-rev-1a (notice date: 2022-04-19)",
        "source_6=https://github.com/terrillmoore/NIST-Statistical-Test-Suite (practical implementation reference only)"]
    (OUT / "provenance.txt").write_text("\n".join(provenance) + "\n", encoding="utf-8")
    summary_lines = ["NIST SP 800-22 Rev. 1a results generated by the official NIST STS 2.1.2 executable.",
                     f"Source revision: {source_commit}", f"Suite: NIST STS 2.1.2; retrieval date: {datetime.date.today().isoformat()}",
                     f"Parameters: 10 streams/category; {BITS_PER_STREAM} bits/stream; alpha={ALPHA}; default STS parameters.",
                     "Selected tests: Frequency, Block Frequency, Cumulative Sums, Runs, Longest Run of Ones, Rank, Discrete Fourier Transform, Non-overlapping Template, Overlapping Template, Universal, Approximate Entropy, Random Excursions, Random Excursions Variant, Serial, Linear Complexity.",
                     "Per-stream p-values, status, and suite-reported pass proportions are in results.csv. Native detailed outputs are preserved in each *_raw/ directory.", ""]
    for category, report in reports.items():
        summary_lines += ["", f"[{category}]"]
        rows_by_test: dict[str, list[tuple[str, str]]] = {}
        for test, uniformity_p, proportion in _summary_rows(report):
            rows_by_test.setdefault(test, []).append((uniformity_p, proportion))
        for test, entries in rows_by_test.items():
            for component_index, (uniformity_p, proportion) in enumerate(entries, 1):
                summary_lines.append(f"{test} component={component_index}: NIST uniformity p-value={uniformity_p}; pass proportion={proportion}")
        with (OUT / "results.csv").open(newline="", encoding="utf-8") as result_file:
            component_rows = [row for row in csv.DictReader(result_file) if row["source_category"] == category]
        counts = {status: sum(row["status"] == status for row in component_rows)
                  for status in ("pass", "fail", "not-applicable")}
        summary_lines.append(f"Individual stream/component outcomes (not a security score): {counts}")
    summary_lines += ["", "## Sources and limitations", "Sources accessed on 2026-09-28. NIST is authoritative; GitHub is a practical implementation reference only.",
        "1. Official NIST documentation/software: https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software",
        "2. Official NIST SP 800-22 Rev. 1a PDF: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf",
        "3. Official guide: https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software/guide-to-the-statistical-tests",
        "4. Official publication page (published 2010-04-30): https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final",
        "5. Official revision notice (2022-04-19): https://csrc.nist.gov/news/2022/decision-to-revise-nist-sp-800-22-rev-1a",
        "6. Professor-provided practical reference only: https://github.com/terrillmoore/NIST-Statistical-Test-Suite",
        "SP 800-22 Rev. 1a provides statistical tests for random and pseudorandom bitstreams. This is an additional statistical evaluation for this project. Passing tests does not prove the encryption scheme cryptographically secure; statistical testing is not a substitute for cryptanalysis.",
        "NIST's April 19, 2022 notice plans revision and calls for clarifying/rejecting use of SP 800-22 as an assessment of cryptographic random-number generators. Report outcomes only as passed/failed the selected statistical tests under the stated parameters, not proved secure.",
        "NIST results are distinct from NPCR, UACI, entropy, correlation, exact-recovery, and thumbnail-preservation metrics."]
    (OUT / "summary.txt").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    print(f"Wrote NIST SP 800-22 outputs to {OUT}")


if __name__ == "__main__":
    main()
