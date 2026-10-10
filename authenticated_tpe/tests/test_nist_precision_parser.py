from __future__ import annotations

import importlib.util
from pathlib import Path


RUNNER_PATH = Path(__file__).parents[1] / "experiments" / "run_nist_sp800_22_comprehensive.py"
spec = importlib.util.spec_from_file_location("nist_runner", RUNNER_PATH)
assert spec and spec.loader
nist_runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nist_runner)


def test_first_level_precision_and_alpha_boundary() -> None:
    exact = "1.2345678901234567e-250"
    assert exact.strip() == exact
    assert nist_runner.classify_first_level_pvalue(exact) == "fail"
    assert nist_runner.classify_first_level_pvalue("0.009999999999999998") == "fail"
    assert nist_runner.classify_first_level_pvalue("0.01") == "pass"
    assert nist_runner.classify_first_level_pvalue("0.010000000000000002") == "pass"


def test_summary_parser_accepts_full_precision_scientific_notation() -> None:
    line = "  10  10  10  10  10  10  10  10  10  10  1.2345678901234567e-250  98/100  Frequency"
    match = nist_runner.REPORT_LINE.match(line)
    assert match is not None
    assert match.group("uniformity") == "1.2345678901234567e-250"
    assert match.group("test") == "Frequency"


def test_raw_result_text_is_not_rounded_or_coerced(tmp_path: Path) -> None:
    p = tmp_path / "results.txt"
    exact = ["1.2345678901234567e-250", "0", "0.010000000000000002"]
    p.write_text("\n".join(exact) + "\n")
    parsed = [line.strip() for line in p.read_text().splitlines() if line.strip()]
    assert parsed == exact
    assert parsed[0] != "0"


def test_random_excursions_and_variant_parse_components_and_na(tmp_path: Path) -> None:
    for test, heading, components in (
        ("RandomExcursions", "RANDOM EXCURSIONS TEST", 8),
        ("RandomExcursionsVariant", "RANDOM EXCURSIONS VARIANT TEST", 18),
    ):
        stats = tmp_path / f"{test}.txt"
        block = heading + "\n" + "\n".join(["SUCCESS p_value = 0.5"] * components)
        stats.write_text("\n".join([block] * (nist_runner.N_STREAMS - 1) + [heading + "\nTEST NOT APPLICABLE"]) + "\n")
        statuses = nist_runner.stats_statuses(test, stats)
        assert len(statuses) == nist_runner.N_STREAMS * components
        assert statuses[:components] == ["pass"] * components
        assert statuses[-components:] == [None] * components


def test_component_count_and_pass_fail_statuses_are_explicit() -> None:
    assert nist_runner.COMPONENT_COUNTS["CumulativeSums"] == 2
    assert nist_runner.COMPONENT_COUNTS["Serial"] == 2
    assert nist_runner.COMPONENT_COUNTS["RandomExcursions"] == 8
    assert nist_runner.COMPONENT_COUNTS["RandomExcursionsVariant"] == 18
    assert nist_runner.classify_first_level_pvalue("0.0000000000000000") == "fail"
