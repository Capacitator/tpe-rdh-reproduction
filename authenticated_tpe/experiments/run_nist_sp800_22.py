#!/usr/bin/env python3
"""Run official NIST STS 2.1.2 on authenticated-TPE deterministic byte streams.

The categories are the authenticated-TPE Step-2 RGB image before RCM tag
embedding and the final RCM-marked RGB image. Neither category is called a
chaotic sequence. This runner follows the original project's NIST protocol and
status parsing without importing or changing its algorithm.
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
import PIL
from PIL import Image

PROJECT = Path(__file__).resolve().parents[1]
REPO = PROJECT.parent
OUT = PROJECT / "output/nist_sp800_22"
sys.path.insert(0, str(PROJECT / "src"))
import authenticated_tpe as auth
from statistical_eval import deterministic_test_image_id, pack_msb_first

BITS_PER_STREAM = 1_000_000
STREAM_COUNT = 10
ALPHA = 0.01
IMAGE_NAMES = ("airplane", "baboon", "couple", "girl", "lena", "peppers",
               "airplane", "baboon", "couple", "girl")
BASE_KEY = hashlib.sha256(b"tpe-rdh-nist-shared-key").digest()
KEYS = [BASE_KEY, BASE_KEY] + [
    hashlib.sha256(f"tpe-rdh-nist-key-{i}".encode()).digest()
    for i in range(2, STREAM_COUNT)
]
SOURCE_DESCRIPTIONS = {
    "step2_intermediate": "Step-2 authenticated-TPE RGB image before RCM tag embedding; row-major RGB uint8 bytes",
    "final_marked_rgb": "final RCM-marked authenticated-TPE RGB image; row-major RGB uint8 bytes",
}
EXACT_COMMAND = "python authenticated_tpe/experiments/run_nist_sp800_22.py --sts-dir <NIST_STS_2_1_2_ROOT>"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_image(name: str) -> tuple[np.ndarray, str]:
    path = REPO / "tpe_rdh_reproduction/input/uct_colour" / f"{name}.tif"
    raw_hash = digest(path.read_bytes())
    with Image.open(path) as im:
        im = im.convert("RGB")
        if im.size != (512, 512):
            if im.size != (256, 256):
                raise ValueError(f"unexpected image dimensions: {path.name} {im.size}")
            im = im.resize((512, 512))
        image = np.asarray(im, dtype=np.uint8)
    return image, raw_hash


def stream_hash(bit_string: str) -> str:
    return digest(bit_string.encode("ascii"))


def parse_status(pvalue: str | None) -> str:
    if pvalue is None or pvalue in {"", "----", "N/A", "nan", "NaN"}:
        return "not-applicable"
    return "pass" if float(pvalue) >= ALPHA else "fail"


def make_streams() -> tuple[list[dict], dict[str, list[str]]]:
    manifest: list[dict] = []
    streams: dict[str, list[str]] = {"step2_intermediate": [], "final_marked_rgb": []}
    for index, name in enumerate(IMAGE_NAMES, 1):
        image, image_file_hash = read_image(name)
        iid = deterministic_test_image_id(f"nist-image-{name}")
        key = KEYS[index - 1]
        step1 = auth._step1_image(image, key, iid)
        step2 = auth._step2_image(step1, key)
        protected = auth.protect_image(image, key, iid)
        verified = auth.verify_and_decrypt(protected.marked_image, key, iid)
        if not verified.accepted or not np.array_equal(verified.recovered_image, image):
            raise RuntimeError(f"NIST input did not pass clean authentication and exact recovery: {name}")
        step2_bits = pack_msb_first(step2)
        marked_bits = pack_msb_first(protected.marked_image)
        streams["step2_intermediate"].append(step2_bits)
        streams["final_marked_rgb"].append(marked_bits)
        manifest.append({
            "stream_index": index,
            "image": name,
            "source_image_path": f"tpe_rdh_reproduction/input/uct_colour/{name}.tif",
            "source_image_file_sha256": image_file_hash,
            "processed_image_sha256": digest(image.tobytes(order="C")),
            "image_id_sha256": digest(iid),
            "user_key_sha256": digest(key),
            "step1_sha256": digest(step1.tobytes(order="C")),
            "step2_sha256": digest(step2.tobytes(order="C")),
            "final_marked_sha256": digest(protected.marked_image.tobytes(order="C")),
            "recovered_sha256": digest(verified.recovered_image.tobytes(order="C")),
            "mode": protected.mode,
            "clean_authenticated_exact_recovery": True,
            "step2_stream_sha256": stream_hash(step2_bits),
            "final_stream_sha256": stream_hash(marked_bits),
            "stream_length_bits": BITS_PER_STREAM,
        })
    return manifest, streams


def summary_rows(report: Path) -> list[tuple[str, str, str]]:
    parsed = []
    for line in report.read_text(errors="replace").splitlines():
        match = re.match(r"\s*(?:[0-9]+\s+){10}(\d+(?:\.\d+)?|----)\s+\*?\s*(\d+/\d+|------)\s+\*?\s*([A-Za-z]+)\s*$", line)
        if match:
            pvalue, proportion, test = match.groups()
            parsed.append((test, pvalue, proportion))
    return parsed


def run_category(sts_root: Path, category: str, bitstreams: list[str]) -> Path:
    input_path = OUT / f"{category}_input_ascii.txt"
    input_path.write_text("\n".join(bitstreams) + "\n", encoding="ascii")
    answers = f"0\n{input_path.resolve()}\n1\n0\n{len(bitstreams)}\n0\n"
    proc = subprocess.run([str(sts_root / "assess"), str(BITS_PER_STREAM)], cwd=sts_root,
                          input=answers, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=1800)
    if "Statistical Testing Complete" not in proc.stdout:
        raise RuntimeError(f"official NIST assess did not complete category {category}: {proc.stdout[-2000:]}")
    experiment_dir = sts_root / "experiments/AlgorithmTesting"
    report = OUT / f"{category}_finalAnalysisReport.txt"
    shutil.copyfile(experiment_dir / "finalAnalysisReport.txt", report)
    report.write_text(report.read_text(errors="replace").replace(
        str(input_path.resolve()), f"authenticated_tpe/output/nist_sp800_22/{input_path.name}"), encoding="utf-8")
    raw = OUT / f"{category}_raw"
    if raw.exists():
        shutil.rmtree(raw)
    shutil.copytree(experiment_dir, raw)
    return report


def write_results(reports: dict[str, Path], manifest: list[dict]) -> None:
    by_index = {int(row["stream_index"]): row for row in manifest}
    fields = ["category", "image", "stream_index", "source_description", "stream_length_bits", "alpha",
              "test_name", "p_value", "status", "test_component", "pass_proportion", "nist_sts_version",
              "source_hashes", "exact_command"]
    with (OUT / "results.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for category, report in reports.items():
            parsed = summary_rows(report)
            tests = list(dict.fromkeys(row[0] for row in parsed))
            raw = OUT / f"{category}_raw"
            for test in tests:
                summaries = [(p, prop) for name, p, prop in parsed if name == test]
                result_file = raw / test / "results.txt"
                vals = []
                if result_file.exists():
                    for token in result_file.read_text(errors="replace").split():
                        try:
                            vals.append(float(token))
                        except ValueError:
                            pass
                components = len(summaries)
                if test in {"RandomExcursions", "RandomExcursionsVariant"}:
                    heading = "RANDOM EXCURSIONS TEST" if test == "RandomExcursions" else "RANDOM EXCURSIONS VARIANT TEST"
                    symbols = ([-4, -3, -2, -1, 1, 2, 3, 4] if test == "RandomExcursions"
                               else list(range(-9, 0)) + list(range(1, 10)))
                    blocks = (raw / test / "stats.txt").read_text(errors="replace").split(heading)
                    for index, block in enumerate(blocks[1:], 1):
                        if index > STREAM_COUNT:
                            break
                        stream_row = by_index[index]
                        hashes = ";".join(f"{k}={stream_row[k]}" for k in (
                            "source_image_file_sha256", "user_key_sha256", "image_id_sha256",
                            "step2_sha256", "final_marked_sha256"))
                        applicable = "TEST NOT APPLICABLE" not in block
                        pvals = re.findall(r"p[-_]value\s*=\s*([0-9.]+)", block) if applicable else []
                        for comp, symbol in enumerate(symbols):
                            pval = pvals[comp] if comp < len(pvals) else None
                            prop = summaries[comp][1] if comp < len(summaries) else ""
                            writer.writerow({"category": category, "image": stream_row["image"],
                                "stream_index": index, "source_description": SOURCE_DESCRIPTIONS[category],
                                "stream_length_bits": BITS_PER_STREAM, "alpha": ALPHA,
                                "test_name": test, "p_value": pval or "", "status": parse_status(pval),
                                "test_component": f"state={symbol}", "pass_proportion": prop,
                                "nist_sts_version": "2.1.2", "source_hashes": hashes, "exact_command": EXACT_COMMAND})
                    continue
                if components == 0 or len(vals) != STREAM_COUNT * components:
                    vals = []
                    components = max(components, 1)
                for index in range(1, STREAM_COUNT + 1):
                    stream_row = by_index[index]
                    hashes = ";".join(f"{k}={stream_row[k]}" for k in (
                        "source_image_file_sha256", "user_key_sha256", "image_id_sha256",
                        "step2_sha256", "final_marked_sha256"))
                    for comp in range(components):
                        pval = vals[(index - 1) * components + comp] if vals else None
                        prop = summaries[comp][1] if comp < len(summaries) else ""
                        writer.writerow({"category": category, "image": stream_row["image"],
                            "stream_index": index, "source_description": SOURCE_DESCRIPTIONS[category],
                            "stream_length_bits": BITS_PER_STREAM, "alpha": ALPHA, "test_name": test,
                            "p_value": "" if pval is None else f"{pval:.8g}",
                            "status": parse_status(None if pval is None else str(pval)),
                            "test_component": f"component={comp + 1}", "pass_proportion": prop,
                            "nist_sts_version": "2.1.2", "source_hashes": hashes, "exact_command": EXACT_COMMAND})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sts-dir", type=Path, required=True,
                        help="official NIST STS 2.1.2 source/build directory used for original project")
    args = parser.parse_args()
    sts_base = args.sts_dir.resolve()
    candidates = [sts_base, sts_base / "sts", sts_base / "sts-2.1.2", sts_base / "sts-2.1.2/sts-2.1.2"]
    sts_root = next((path for path in candidates if (path / "assess").is_file()), None)
    if sts_root is None:
        raise FileNotFoundError(f"could not find built official STS assess under {sts_base}")
    source_commit = subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip()
    source_state = "dirty" if subprocess.check_output(["git", "-C", str(REPO), "status", "--porcelain"], text=True).strip() else "clean"
    OUT.mkdir(parents=True, exist_ok=True)
    manifest, streams = make_streams()
    with (OUT / "stream_manifest.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(manifest[0]), lineterminator="\n")
        writer.writeheader(); writer.writerows(manifest)
    reports = {category: run_category(sts_root, category, data) for category, data in streams.items()}
    write_results(reports, manifest)
    for category in reports:
        shutil.rmtree(OUT / f"{category}_raw")
    git_sts = subprocess.run(["git", "-C", str(sts_root.parent), "rev-parse", "HEAD"],
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    sts_revision = git_sts.stdout.strip() if git_sts.returncode == 0 else "official NIST STS 2.1.2 distribution"
    key_hashes = ",".join(f"stream{i + 1}:{digest(key)}" for i, key in enumerate(KEYS))
    input_hashes = ",".join(f"{r['image']}:{r['source_image_file_sha256']}" for r in manifest)
    (OUT / "provenance.txt").write_text("\n".join([
        "experiment=authenticated-TPE statistical and differential evaluation",
        "nist_sts_version=2.1.2", f"nist_sts_revision={sts_revision}",
        f"nist_assess_sha256={digest((sts_root / 'assess').read_bytes())}",
        f"source_commit={source_commit}", f"source_worktree={source_state} at run start",
        f"python={platform.python_version()}", f"numpy={np.__version__}",
        f"pillow={PIL.__version__}", *(f"{name}={importlib.metadata.version(name)}" for name in ("pytest", "matplotlib", "scikit-image", "scipy")),
        f"streams_per_category={STREAM_COUNT}", f"stream_length_bits={BITS_PER_STREAM}", f"alpha={ALPHA}",
        "selected_tests=Frequency,BlockFrequency,CumulativeSums,Runs,LongestRun,Rank,FFT,NonOverlappingTemplate,OverlappingTemplate,Universal,ApproximateEntropy,RandomExcursions,RandomExcursionsVariant,Serial,LinearComplexity",
        "parameters=Block Frequency M=128; non-overlap template m=9; overlap template m=9; approximate entropy m=10; serial m=16; linear complexity M=500; other parameters use STS 2.1.2 defaults",
        f"image_order={','.join(IMAGE_NAMES)}",
        f"key_fixtures=original NIST key schedule; hashes only: {key_hashes}",
        "image_id_policy=deterministic public SHA-256 fixture of image label; hashes only in manifest; same ID for repeated image labels",
        f"input_image_file_sha256={input_hashes}",
        "step2_conversion=actual Step-2 RGB uint8 image before RCM; C-order row-major RGB bytes; MSB-first; first 1,000,000 bits",
        "final_conversion=final RCM-marked RGB uint8 output; C-order row-major RGB bytes; MSB-first; first 1,000,000 bits",
        "step2_is_not_a_chaotic_sequence=true; it is a keyed image intermediate, tested only as the byte stream described above",
        "grouping_seed=deterministic HMAC_DRBG from channel structure keys; no nondeterministic generator seeds used",
        f"exact_command={EXACT_COMMAND}", f"runner_script_sha256={digest(Path(__file__).read_bytes())}",
        f"evaluation_helper_sha256={digest((PROJECT / 'src/statistical_eval.py').read_bytes())}",
        f"authenticated_source_sha256={digest((PROJECT / 'src/authenticated_tpe.py').read_bytes())}",
        f"stream_manifest_sha256={digest((OUT / 'stream_manifest.csv').read_bytes())}",
        "status_interpretation=official workflow: p-value >= alpha is pass; p-value < alpha is fail; unavailable or STS-not-applicable component is not-applicable",
        "No user key bytes or ImageID bytes are written; only SHA-256 digests are recorded.",
    ]) + "\n", encoding="utf-8")
    results = list(csv.DictReader((OUT / "results.csv").open(newline="", encoding="utf-8")))
    lines = ["NIST SP 800-22 Rev. 1a results from official NIST STS 2.1.2.",
             "This is a statistical diagnostic of the listed deterministic authenticated-TPE byte streams, not a security proof.",
             "No overall pass score is computed. Outcomes are reported for every stream/test component.",
             f"Parameters: {STREAM_COUNT} streams/category; {BITS_PER_STREAM} bits/stream; alpha={ALPHA}; STS 2.1.2 settings in provenance.txt."]
    for category in SOURCE_DESCRIPTIONS:
        subset = [r for r in results if r["category"] == category]
        counts = {s: sum(row["status"] == s for row in subset) for s in ("pass", "fail", "not-applicable")}
        lines += ["", f"[{category}] {SOURCE_DESCRIPTIONS[category]}",
                  f"All stream/component outcomes: {counts}", "Test: pass / fail / not-applicable", "| Test | pass | fail | not-applicable |", "|---|---:|---:|---:|"]
        for test in dict.fromkeys(row["test_name"] for row in subset):
            selected = [row for row in subset if row["test_name"] == test]
            lines.append(f"| {test} | {sum(r['status']=='pass' for r in selected)} | {sum(r['status']=='fail' for r in selected)} | {sum(r['status']=='not-applicable' for r in selected)} |")
    lines += ["", "Interpretation: these are statistical diagnostics for the deterministic byte streams described in provenance. Mixed failures and passes neither prove nor disprove cryptographic security; SP 800-22, NPCR, and UACI are not proofs of security."]
    (OUT / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "README.md").write_text(f"""# Authenticated-TPE NIST SP 800-22 evaluation

Generated by `authenticated_tpe/experiments/run_nist_sp800_22.py` using the official NIST STS 2.1.2 `assess` executable and the original project's parameter and status workflow. Run from the repository root:

```bash
python authenticated_tpe/experiments/run_nist_sp800_22.py --sts-dir <NIST_STS_2_1_2_ROOT>
```

This run tests two distinct deterministic byte-stream categories: (1) the actual Step-2 keyed RGB image before RCM tag embedding, and (2) the final RCM-marked RGB output. The Step-2 source is an authenticated-TPE image intermediate, **not a chaotic sequence**. Both serialize RGB uint8 pixels in C-order, row-major, MSB-first and truncate to 1,000,000 bits. Ten streams use the original NIST image order and key fixtures. ImageID fixtures are deterministic per image label; only their SHA-256 digests are stored.

NIST uses the original experiment's STS 2.1.2, alpha 0.01, stream length, selected tests and special parameters (details in `provenance.txt`). `results.csv` records category, image, stream, source description and hashes, p-values, and pass/fail/not-applicable outcomes. The official thresholds are retained: p-value >= alpha is pass, below alpha is fail, absent or native STS-not-applicable outcomes remain not applicable. No overall “NIST pass” score is reported.

`stream_manifest.csv`, category ASCII stream files, and native `*_finalAnalysisReport.txt` reports are retained. All source hashes and the exact command are in `provenance.txt`. Inputs are the shared UCT files under `tpe_rdh_reproduction/input/uct_colour/`; only the two 256x256 sources are resized to 512x512 using Pillow's default `Image.resize` behavior.

SP 800-22 is a statistical diagnostic of these generated streams. Its outcomes, like NPCR/UACI, do not prove cryptographic security and do not replace cryptanalysis. NIST failures are preserved as observed.
""", encoding="utf-8")
    print(f"NIST STS {sts_revision}; wrote {OUT / 'results.csv'} ({len(results)} stream/component rows)")


if __name__ == "__main__":
    main()
