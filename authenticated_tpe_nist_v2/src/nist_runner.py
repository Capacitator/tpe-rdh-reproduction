"""Drive the official NIST STS 2.1.2 ``assess`` executable and parse its output.

Nothing in this module computes a substitute randomness score: it prepares the
official ASCII input, runs the official binary, preserves the official reports
and then *parses* them.  The only independent computation is the second-level
uniformity p-value, recomputed from the suite's own C1..C10 histogram so that
full-precision values are available alongside the suite's 6-decimal printout.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

import numpy as np
from scipy.special import gammaincc

RESULTS_SUBDIR = Path("experiments") / "AlgorithmTesting"

# Number of independent p-value components each STS test writes per stream.
TEST_COMPONENTS: dict[str, int] = {
    "Frequency": 1,
    "BlockFrequency": 1,
    "CumulativeSums": 2,
    "Runs": 1,
    "LongestRun": 1,
    "Rank": 1,
    "FFT": 1,
    "NonOverlappingTemplate": 148,
    "OverlappingTemplate": 1,
    "Universal": 1,
    "ApproximateEntropy": 1,
    "RandomExcursions": 8,
    "RandomExcursionsVariant": 18,
    "Serial": 2,
    "LinearComplexity": 1,
}

TEST_LABELS = {
    "Frequency": "Frequency Test",
    "BlockFrequency": "Block Frequency Test",
    "CumulativeSums": "Cumulative Sums Test",
    "Runs": "Runs Test",
    "LongestRun": "Longest Run of Ones Test",
    "Rank": "Binary Matrix Rank Test",
    "FFT": "Discrete Fourier Transform Test",
    "NonOverlappingTemplate": "Non-overlapping Template Matching Test",
    "OverlappingTemplate": "Overlapping Template Matching Test",
    "Universal": "Maurer's Universal Statistical Test",
    "ApproximateEntropy": "Approximate Entropy Test",
    "RandomExcursions": "Random Excursions Test",
    "RandomExcursionsVariant": "Random Excursions Variant Test",
    "Serial": "Serial Test",
    "LinearComplexity": "Linear Complexity Test",
}

TEST_ORDER = list(TEST_COMPONENTS)

_COMPONENT_LABELS = {
    "CumulativeSums": ("forward", "reverse"),
    "Serial": ("m", "m-1"),
    "RandomExcursions": tuple(f"state={s}" for s in (-4, -3, -2, -1, 1, 2, 3, 4)),
    "RandomExcursionsVariant": tuple(f"state={s}" for s in list(range(-9, 0)) + list(range(1, 10))),
    "NonOverlappingTemplate": tuple(f"template={i}" for i in range(1, 149)),
}


def component_label(test: str, index: int) -> str:
    labels = _COMPONENT_LABELS.get(test)
    if labels is None:
        return "component=1"
    return labels[index]


# --------------------------------------------------------------------------
# Running the suite
# --------------------------------------------------------------------------
def clean_results(sts_root: Path) -> None:
    target = sts_root / RESULTS_SUBDIR
    for child in target.iterdir():
        if child.is_dir():
            for item in child.iterdir():
                item.unlink()
        elif child.is_file():
            child.unlink()
    target.mkdir(parents=True, exist_ok=True)


def run_assess(sts_root: Path, ascii_path: Path, num_streams: int,
               bits_per_stream: int, log_path: Path, timeout: int = 7200) -> str:
    """Run official ``assess`` in ASCII input mode with all tests, default parameters."""
    answers = f"0\n{ascii_path.resolve()}\n1\n0\n{num_streams}\n0\n"
    proc = subprocess.run([str(sts_root / "assess"), str(bits_per_stream)],
                          cwd=sts_root, input=answers, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout)
    log_path.write_text(proc.stdout, encoding="utf-8", errors="replace")
    if "Statistical Testing Complete" not in proc.stdout:
        raise RuntimeError(f"official assess did not complete; see {log_path}")
    return proc.stdout


def collect_reports(sts_root: Path, out_dir: Path, category: str) -> dict[str, Path]:
    """Copy the official report plus per-test first-level result files."""
    results_dir = sts_root / RESULTS_SUBDIR
    raw_dir = out_dir / "nist_raw" / category
    if raw_dir.exists():
        shutil.rmtree(raw_dir)
    raw_dir.mkdir(parents=True)
    report = results_dir / "finalAnalysisReport.txt"
    text = report.read_text(errors="replace")
    (raw_dir / "finalAnalysisReport.txt").write_text(text, encoding="utf-8")
    for test in TEST_ORDER:
        test_dir = results_dir / test
        if not test_dir.is_dir():
            continue
        for name in ("results.txt", "stats.txt"):
            source = test_dir / name
            if source.is_file():
                (raw_dir / f"{test}__{name}").write_bytes(source.read_bytes())
    return {"raw_dir": raw_dir, "report": raw_dir / "finalAnalysisReport.txt"}


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
_ROW = re.compile(
    r"^\s*(?:\d+\s+){10}(\d+(?:\.\d+)?|----|N/A)\s+\*?\s*(\d+/\d+|N/A|----|------)\s+\*?\s*([A-Za-z]+)\s*$")


def parse_second_level(report_path: Path) -> list[dict]:
    """Uniformity histogram rows from the official finalAnalysisReport.txt."""
    rows = []
    for line in report_path.read_text(errors="replace").splitlines():
        match = _ROW.match(line)
        if not match:
            continue
        p_value, proportion, test = match.groups()
        counts = [int(x) for x in re.findall(r"\d+", line[:60])][:10]
        rows.append({"test": test, "report_p_value": p_value,
                     "report_proportion": proportion, "bins": counts,
                     "chi_square": None, "uniformity_p_value": None,
                     "expected_pass": None})
    # attach the recomputed chi-square / uniformity p-value to each row of a test
    by_test: dict[str, list[dict]] = {}
    for index, row in enumerate(rows):
        by_test.setdefault(row["test"], []).append(row)
    for test, group in by_test.items():
        for index, row in enumerate(group):
            bins = row["bins"]
            total = sum(bins)
            # The suite uses integer division for the expected bin count
            # (expCount = sampleSize/10 in C) and prints "----" when it is 0.
            expected = total // 10
            if expected == 0:
                row["recomputed_component"] = index + 1
                continue
            chi_square = float(np.sum([(count - expected) ** 2 / expected for count in bins]))
            row["chi_square"] = chi_square
            row["uniformity_p_value"] = float(gammaincc(4.5, chi_square / 2.0))
            row["recomputed_component"] = index + 1
    return rows


def parse_first_level(raw_dir: Path, num_streams: int) -> tuple[list[dict], list[str]]:
    """Per-stream, per-component p-values from the official results.txt files."""
    warnings: list[str] = []
    records: list[dict] = []
    for test in TEST_ORDER:
        components = TEST_COMPONENTS[test]
        path = raw_dir / f"{test}__results.txt"
        if not path.is_file():
            warnings.append(f"{test}: official results.txt missing")
            continue
        values = []
        for token in path.read_text(errors="replace").split():
            try:
                values.append(float(token))
            except ValueError:
                pass
        if test in ("RandomExcursions", "RandomExcursionsVariant"):
            records.extend(_parse_random_excursions(raw_dir, test, components, num_streams, warnings))
            continue
        expected = num_streams * components
        if len(values) != expected:
            warnings.append(f"{test}: expected {expected} first-level values, found {len(values)}")
        for stream in range(num_streams):
            for component in range(components):
                flat = stream * components + component
                p_value = values[flat] if flat < len(values) else None
                records.append(_record(test, stream + 1, component, p_value))
    return records, warnings


def _parse_random_excursions(raw_dir: Path, test: str, components: int,
                             num_streams: int, warnings: list[str]) -> list[dict]:
    stats_path = raw_dir / f"{test}__stats.txt"
    heading = ("RANDOM EXCURSIONS TEST" if test == "RandomExcursions"
               else "RANDOM EXCURSIONS VARIANT TEST")
    text = stats_path.read_text(errors="replace")
    blocks = text.split(heading)[1:]
    records: list[dict] = []
    for stream in range(num_streams):
        block = blocks[stream] if stream < len(blocks) else ""
        if "TEST NOT APPLICABLE" in block or not block:
            if block:
                warnings.append(f"{test}: stream {stream + 1} reported not applicable")
            for component in range(components):
                records.append(_record(test, stream + 1, component, None, not_applicable=True))
            continue
        p_values = re.findall(r"p[-_]value\s*=\s*([0-9.eE+-]+)", block)
        if len(p_values) != components:
            warnings.append(f"{test}: stream {stream + 1} reported {len(p_values)} "
                            f"of {components} components")
        for component in range(components):
            p_value = float(p_values[component]) if component < len(p_values) else None
            records.append(_record(test, stream + 1, component, p_value,
                                   not_applicable=p_value is None))
    return records


def _record(test: str, stream: int, component: int, p_value: float | None,
            not_applicable: bool = False) -> dict:
    return {"test_name": test, "test_label": TEST_LABELS[test], "stream_index": stream,
            "test_component": component + 1, "component_label": component_label(test, component),
            "p_value": p_value, "not_applicable": not_applicable}


def summarise(records: list[dict], alpha: float) -> list[dict]:
    """Pass/fail/N/A counts and dominant outcome per (test, component)."""
    out = []
    keys: dict[tuple[str, int], list[dict]] = {}
    for record in records:
        keys.setdefault((record["test_name"], record["test_component"]), []).append(record)
    for (test, component), group in keys.items():
        passed = sum(1 for r in group if r["p_value"] is not None and r["p_value"] >= alpha)
        failed = sum(1 for r in group if r["p_value"] is not None and r["p_value"] < alpha)
        na = sum(1 for r in group if r["p_value"] is None)
        out.append({"test_name": test, "test_label": TEST_LABELS[test],
                    "test_component": component,
                    "component_label": component_label(test, component - 1),
                    "streams": len(group), "pass": passed, "fail": failed,
                    "not_applicable": na,
                    "pass_proportion": (passed / (passed + failed)) if (passed + failed) else None})
    return out


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
