#!/usr/bin/env python3
"""NIST SP 800-22 on actual encrypted E images and recovered images.

The reference specification defines E as Step 1 followed by Step 2; RCM
authentication marking is applied afterward and is excluded from these inputs.
One stream per each of the six fixed public UCT images is used. There are no
replicas or extra key/identifier contexts to inflate the sample count.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np
from PIL import Image

PROJECT = Path(__file__).resolve().parents[1]
REPO = PROJECT.parent
UCT = REPO / "tpe_rdh_reproduction" / "input" / "uct_colour"
OUT = PROJECT / "output" / "nist_encrypted_decrypted_images"
IMAGES = ("airplane", "baboon", "couple", "girl", "lena", "peppers")
ALPHA = 0.01
STREAM_BITS = 1_000_000
STREAM_BYTES = STREAM_BITS // 8
TEST_NAMES = (
    "Frequency", "BlockFrequency", "CumulativeSums", "Runs", "LongestRun",
    "Rank", "FFT", "NonOverlappingTemplate", "OverlappingTemplate",
    "Universal", "ApproximateEntropy", "RandomExcursions",
    "RandomExcursionsVariant", "Serial", "LinearComplexity",
)
COMPONENT_COUNTS = {
    "Frequency": 1, "BlockFrequency": 1, "CumulativeSums": 2, "Runs": 1,
    "LongestRun": 1, "Rank": 1, "FFT": 1, "NonOverlappingTemplate": 148,
    "OverlappingTemplate": 1, "Universal": 1, "ApproximateEntropy": 1,
    "RandomExcursions": 8, "RandomExcursionsVariant": 18, "Serial": 2,
    "LinearComplexity": 1,
}
REPORT_LINE = re.compile(
    r"^\s*(?:\d+\s+){10}(?P<uniformity>(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|----)\s+\*?\s*"
    r"(?P<proportion>\d+/\d+|------)\s+\*?\s*(?P<test>[A-Za-z]+)\s*$"
)
BITS = tuple(f"{n:08b}".encode("ascii") for n in range(256))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture(domain: bytes, index: int, length: int) -> bytes:
    """Match the established authenticated-TPE NIST experiment fixtures."""
    return hashlib.sha256(domain + b"\x00" + index.to_bytes(4, "big")).digest()[:length]


def write_csv(path: Path, rows: list[dict], fields: list[str] | None = None) -> None:
    if fields is None:
        fields = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def load_image(name: str) -> tuple[np.ndarray, bytes]:
    source = UCT / f"{name}.tif"
    source_bytes = source.read_bytes()
    with Image.open(source) as image:
        rgb = image.convert("RGB")
        if rgb.size != (512, 512):
            rgb = rgb.resize((512, 512))
        array = np.asarray(rgb, dtype=np.uint8)
    if array.shape != (512, 512, 3):
        raise ValueError(f"Expected normalized 512x512 RGB image: {name}")
    return np.ascontiguousarray(array), source_bytes


def generate_inputs() -> list[dict]:
    sys.path.insert(0, str(PROJECT / "src"))
    import authenticated_tpe as auth

    raw_root = OUT / "raw_streams"
    shutil.rmtree(raw_root, ignore_errors=True)
    raw_root.mkdir(parents=True, exist_ok=True)
    output_rows: list[dict] = []
    paths = {"encrypted": raw_root / "encrypted_image.bin", "decrypted": raw_root / "decrypted_image.bin"}
    handles = {name: path.open("wb") for name, path in paths.items()}
    try:
        seen: dict[str, set[str]] = {name: set() for name in paths}
        for stream_index, image_name in enumerate(IMAGES, 1):
            image, source_bytes = load_image(image_name)
            user_key = fixture(b"auth-tpe-nist-key-v1", stream_index, 32)
            image_id = fixture(b"auth-tpe-nist-image-id-v1", stream_index, 16)

            # Paper Section 4: encrypted image E is Step 1 followed by Step 2.
            # Tag embedding is a later stage and is never included in this array.
            step1 = auth._step1_image(image, user_key, image_id)
            encrypted = auth._step2_image(step1, user_key)

            protected = auth.protect_image(image, user_key, image_id)
            verified = auth.verify_and_decrypt(protected.marked_image, user_key, image_id)
            if not verified.accepted or verified.recovered_image is None:
                raise AssertionError(f"Actual decrypt/authentication failed for {image_name}")
            decrypted = verified.recovered_image
            if not np.array_equal(decrypted, image):
                raise AssertionError(f"Recovery was not bit-exact for {image_name}")

            arrays = {"encrypted": encrypted, "decrypted": decrypted}
            for category, array in arrays.items():
                full_bytes = array.tobytes(order="C")
                stream = full_bytes[:STREAM_BYTES]
                digest = sha(stream)
                if digest in seen[category]:
                    raise AssertionError(f"Duplicate {category} stream found")
                seen[category].add(digest)
                handles[category].write(stream)
                output_rows.append({
                    "category": category,
                    "stream_index": stream_index,
                    "image": image_name,
                    "source_file": f"tpe_rdh_reproduction/input/uct_colour/{image_name}.tif",
                    "source_file_sha256": sha(source_bytes),
                    "normalized_rgb_array_sha256": sha(image.tobytes(order="C")),
                    "tested_array_sha256": sha(full_bytes),
                    "stream_sha256": digest,
                    "stream_length_bits": STREAM_BITS,
                    "stream_bytes": STREAM_BYTES,
                    "full_image_bytes": len(full_bytes),
                    "dimensions_channels_dtype": "512x512x3 RGB uint8",
                    "block_size": "32x32",
                    "group_definition": "4 distinct blocks per channel; 64 groups per channel; key-dependent Fisher-Yates grouping",
                    "user_key_sha256": sha(user_key),
                    "image_id_sha256": sha(image_id),
                    "key_fixture_domain": "auth-tpe-nist-key-v1",
                    "image_id_fixture_domain": "auth-tpe-nist-image-id-v1",
                    "fixture_index": stream_index,
                    "byte_to_bit": "MSB-first; NIST binary mode consumes each byte high bit first",
                    "sample_selection": "first 125000 row-major RGB bytes from this actual image output; one sample per fixed image, no replication",
                    "authentication_info_in_tested_array": False,
                    "authentication_accepted": verified.accepted,
                    "exact_recovery": bool(np.array_equal(decrypted, image)),
                    "protection_mode": protected.mode,
                })
            print(f"generated actual encrypted and recovered outputs: {stream_index}/6 ({image_name})", flush=True)
    finally:
        for handle in handles.values():
            handle.close()
    return output_rows


def parse_report(path: Path) -> tuple[dict[str, list[dict]], dict[str, int]]:
    rows: dict[str, list[dict]] = {name: [] for name in TEST_NAMES}
    for line in path.read_text(errors="replace").splitlines():
        match = REPORT_LINE.match(line)
        if match:
            rows[match.group("test")].append({"uniformity": match.group("uniformity"), "proportion": match.group("proportion")})
    for name, count in COMPONENT_COUNTS.items():
        if len(rows[name]) != count:
            raise AssertionError(f"{name}: expected {count} STS summary components, got {len(rows[name])}")
    return rows, {name: count for name, count in COMPONENT_COUNTS.items()}


def component_names(test: str, sts_root: Path) -> list[str]:
    if test == "CumulativeSums": return ["forward", "reverse"]
    if test == "Serial": return ["delta_1", "delta_2"]
    if test == "RandomExcursions": return [f"state={x}" for x in (-4, -3, -2, -1, 1, 2, 3, 4)]
    if test == "RandomExcursionsVariant": return [f"state={x}" for x in (*range(-9, 0), *range(1, 10))]
    if test == "NonOverlappingTemplate":
        return [f"m=9 template={x.strip()}" for x in (sts_root / "templates/template9").read_text().splitlines() if x.strip()]
    return ["single"]


def parse_statuses(test: str, stats: str, count: int) -> list[list[str | None]]:
    ncomp = COMPONENT_COUNTS[test]
    if test in ("RandomExcursions", "RandomExcursionsVariant"):
        heading = "RANDOM EXCURSIONS VARIANT TEST" if test.endswith("Variant") else "RANDOM EXCURSIONS TEST"
        blocks = re.split(heading, stats, flags=re.I)[1:]
        if len(blocks) != count:
            raise AssertionError(f"{test}: expected {count} raw stream sections, got {len(blocks)}")
        result = []
        for block in blocks:
            if "TEST NOT APPLICABLE" in block:
                result.append([None] * ncomp)
            else:
                marks = re.findall(r"\b(SUCCESS|FAILURE)\b", block)
                if len(marks) != ncomp:
                    raise AssertionError(f"{test}: expected {ncomp} native status markers, got {len(marks)}")
                result.append(["pass" if m == "SUCCESS" else "fail" for m in marks])
        return result
    if test == "Runs":
        blocks = re.split(r"RUNS TEST", stats, flags=re.I)[1:]
        result = []
        for block in blocks:
            if "PI ESTIMATOR CRITERIA NOT MET" in block:
                result.append(["fail"])
            else:
                mark = re.search(r"\b(SUCCESS|FAILURE)\b\s+p_value", block)
                if not mark: raise AssertionError("Runs test lacks an STS status marker")
                result.append(["pass" if mark.group(1) == "SUCCESS" else "fail"])
        if len(result) != count: raise AssertionError("Runs stream count mismatch")
        return result
    if test == "LinearComplexity":
        return []  # statuses are derived from the official full-precision results below
    marks = re.findall(r"\b(SUCCESS|FAILURE)\b", stats)
    if len(marks) != count * ncomp:
        raise AssertionError(f"{test}: expected {count*ncomp} native statuses, got {len(marks)}")
    return [["pass" if marks[i*ncomp+c] == "SUCCESS" else "fail" for c in range(ncomp)] for i in range(count)]


def run_sts(sts_source: Path, inputs: dict[str, Path]) -> tuple[list[dict], list[dict]]:
    component_rows: list[dict] = []
    uniformity_rows: list[dict] = []
    raw_root = OUT / "raw_reports"
    shutil.rmtree(raw_root, ignore_errors=True)
    raw_root.mkdir(parents=True, exist_ok=True)
    for category, input_path in inputs.items():
        runtime = Path(tempfile.mkdtemp(prefix=f".sts_actual_{category}_", dir=OUT))
        sts_root = runtime / "sts"
        shutil.copytree(sts_source, sts_root)
        try:
            exp = sts_root / "experiments/AlgorithmTesting"
            shutil.rmtree(exp, ignore_errors=True)
            for name in TEST_NAMES:
                (exp / name).mkdir(parents=True, exist_ok=True)
            answers = f"0\n{input_path.resolve()}\n1\n0\n6\n1\n"
            proc = subprocess.run([str(sts_root / "assess"), str(STREAM_BITS)], cwd=sts_root, input=answers, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=6*60*60)
            if "Statistical Testing Complete" not in proc.stdout:
                raise RuntimeError(f"STS failed for {category}:\n{proc.stdout[-4000:]}")
            destination = raw_root / category
            shutil.copytree(exp, destination)
            report = destination / "finalAnalysisReport.txt"
            report_rows, _ = parse_report(report)
            freq_lines = re.findall(r"BITSREAD\s*=\s*(\d+)\s+0s\s*=\s*(\d+)\s+1s\s*=\s*(\d+)", (destination / "freq.txt").read_text(errors="replace"))
            raw = input_path.read_bytes()
            if len(freq_lines) != 6 or any(int(row[0]) != STREAM_BITS for row in freq_lines):
                raise AssertionError(f"STS did not consume six {STREAM_BITS}-bit streams for {category}")
            for si, row in enumerate(freq_lines):
                chunk = raw[si * STREAM_BYTES:(si + 1) * STREAM_BYTES]
                ones = sum(byte.bit_count() for byte in chunk)
                if (int(row[1]), int(row[2])) != (STREAM_BITS - ones, ones):
                    raise AssertionError(f"STS binary input differs from recorded stream {si + 1} in {category}")
            for test in TEST_NAMES:
                ncomp = COMPONENT_COUNTS[test]
                test_dir = destination / test
                pvalues = [x.strip() for x in (test_dir / "results.txt").read_text(errors="replace").splitlines() if x.strip()]
                if len(pvalues) != 6*ncomp:
                    raise AssertionError(f"{category}/{test}: expected {6*ncomp} p-values, got {len(pvalues)}")
                stats = (test_dir / "stats.txt").read_text(errors="replace")
                statuses = parse_statuses(test, stats, 6)
                labels = component_names(test, sts_root)
                if len(labels) != ncomp:
                    raise AssertionError(f"{test}: expected {ncomp} component labels, got {len(labels)}")
                if test == "LinearComplexity":
                    statuses = [["pass" if float(pvalues[si*ncomp]) >= ALPHA else "fail"] for si in range(6)]
                for ci in range(ncomp):
                    native_proportion = report_rows[test][ci]["proportion"]
                    applicable = [statuses[si][ci] for si in range(6) if statuses and statuses[si][ci] is not None]
                    if native_proportion not in ("------", ""):
                        numerator, denominator = (int(value) for value in native_proportion.split("/", 1))
                        actual_passes = sum(value == "pass" for value in applicable)
                        if numerator != actual_passes or denominator != len(applicable):
                            raise AssertionError(f"{category}/{test}/{labels[ci]}: STS proportion {native_proportion} disagrees with parsed outcomes")
                for ci in range(ncomp):
                    native = report_rows[test][ci]
                    uniformity_rows.append({"category": category, "test": test, "component": labels[ci], "second_level_uniformity_p_value": native["uniformity"], "pass_proportion": native["proportion"], "streams": 6, "uniformity_status": "not_computed_by_STS (fewer than 55 streams)" if native["uniformity"] == "----" else "computed_by_STS"})
                    for si, image_name in enumerate(IMAGES):
                        p = pvalues[si*ncomp+ci]
                        status = statuses[si][ci] if statuses else ("pass" if float(p) >= ALPHA else "fail")
                        if status is None:
                            p_status, shown = "not_applicable", "N/A"
                        elif test == "Runs" and "PI ESTIMATOR CRITERIA NOT MET" in re.split(r"RUNS TEST", stats, flags=re.I)[1:][si]:
                            p_status, shown = "algorithm_defined_zero (Runs criterion unmet)", "algorithm-defined zero"
                        elif float(p) == 0.0:
                            p_status, shown = "double_underflow_lt_1e-300", "<1e-300"
                        else:
                            p_status, shown = "reported_by_STS_full_precision", p
                        component_rows.append({"category": category, "test": test, "component": labels[ci], "image": image_name, "stream_index": si+1, "first_level_p_value": shown, "raw_STS_p_value": p if status is not None else "", "p_value_status": p_status, "first_level_result": status or "N/A", "alpha": ALPHA, "pass_criterion": "STS SUCCESS and p >= 0.01", "individual_streams": 6})
            print(f"official STS completed: {category}", flush=True)
        finally:
            shutil.rmtree(runtime, ignore_errors=True)
    return component_rows, uniformity_rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sts-source", type=Path, required=True, help="Official NIST STS 2.1.2 source tree with precision-only patch already applied and built")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    output_rows = generate_inputs()
    categories = ("encrypted", "decrypted")
    inputs = {name: OUT / "raw_streams" / f"{name}_image.bin" for name in categories}
    write_csv(OUT / "stream_manifest.csv", output_rows)
    component_rows, uniformity_rows = run_sts(args.sts_source.resolve(), inputs)
    write_csv(OUT / "first_level_p_values.csv", component_rows)
    write_csv(OUT / "second_level_uniformity.csv", uniformity_rows)
    counts = {}
    for category in categories:
        current = [r for r in component_rows if r["category"] == category]
        counts[category] = {status: sum(r["first_level_result"] == status for r in current) for status in ("pass", "fail", "N/A")}
    (OUT / "summary.json").write_text(json.dumps({"alpha": ALPHA, "pass_criterion": "STS SUCCESS and individual p-value >= 0.01", "images": list(IMAGES), "unique_image_streams_per_category": 6, "claimed_independent_random_streams": 0, "independence_note": "Six distinct public source images and one fixed key/ImageID context per image. The image streams are not claimed to be independent draws from a random generator; second-level uniformity is N/A because STS requires at least 55 streams.", "bits_per_stream": STREAM_BITS, "counts": counts}, indent=2)+"\n", encoding="utf-8")
    (OUT / "README.md").write_text(
        "# NIST evaluation of actual encrypted and recovered images\n\n"
        "The professor-supplied specification (Section 4, p. 5) defines the encrypted block E as the output of Step 1 followed by Step 2. RCM authentication marking is subsequent; no tag or authentication payload is included in the encrypted or decrypted tested arrays. The actual protected marked image is passed through `verify_and_decrypt`; only its recovered image is used as the decrypted NIST input. All six recoveries were byte-exact.\n\n"
        "Each category contains one 1,000,000-bit prefix from each of the six fixed UCT images, RGB row-major bytes packed MSB-first. Images are normalized as 512x512 RGB uint8. Blocks are 32x32; groups contain four distinct blocks per channel, 64 groups per channel. The same deterministic public fixture rule used in the previous authenticated-TPE NIST experiment supplies one UserKey and ImageID context per image (indices 1 through 6). No image, key, or identifier was replicated to increase the sample count. These are six distinct image outputs; independence as random observations is not established.\n\n"
        "STS 2.1.2 was run with its default 15-test suite, alpha=0.01, six streams/category, and 1,000,000 bits/stream. An individual result passes when STS reports SUCCESS and p >= 0.01. Second-level uniformity is not computed by STS at n=6 (below 55); the official `----` values are preserved. `first_level_p_values.csv` contains one row per image and test component; `second_level_uniformity.csv` preserves official second-level output. A numerical zero emitted after the double-precision STS calculation is labeled `<1e-300` with an explicit underflow status; a Runs-test estimator-criterion zero is labeled separately.\n\n"
        "Files: `stream_manifest.csv`, `raw_streams/`, `raw_reports/`, `first_level_p_values.csv`, `second_level_uniformity.csv`, `summary.json`.\n", encoding="utf-8")
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
