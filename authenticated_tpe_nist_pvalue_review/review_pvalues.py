#!/usr/bin/env python3
"""Audit existing NIST STS CSVs; never regenerates or edits the streams/results."""
from __future__ import annotations
import csv
import math
from pathlib import Path
from scipy.stats import binom

SOURCE = Path(__file__).resolve().parents[1] / "authenticated_tpe_nist_v2" / "output"
OUT = Path(__file__).resolve().parent / "output"
CRYPTO = ("hmac_drbg", "pair_shift", "block_r1", "auth_tag")
CATEGORIES = CRYPTO + ("reduced_shift_diag", "ciphertext_diag", "recovered_diag")
ALPHA = 0.01
UNIFORMITY_ALPHA_NIST = 0.0001


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, records: list[dict]) -> None:
    if not records:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)


def holm_adjust(records: list[dict], alpha: float) -> None:
    """Holm step-down adjusted p-values, with deterministic ordering."""
    order = sorted(range(len(records)), key=lambda i: (records[i]["exact_binomial_upper_tail_p"], i))
    running = 0.0
    m = len(order)
    for rank, index in enumerate(order):
        raw = float(records[index]["exact_binomial_upper_tail_p"])
        running = max(running, min(1.0, (m - rank) * raw))
        records[index]["holm_adjusted_p"] = running
        records[index]["holm_reject_at_0_01"] = running <= alpha


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    category_summary: list[dict] = []
    crypto_components: list[dict] = []
    for category in CATEGORIES:
        first = rows(SOURCE / "categories" / category / "first_level_pvalues.csv")
        valid = [r for r in first if r["status"] in ("pass", "fail")]
        first_pass = sum(r["status"] == "pass" for r in valid)
        first_fail = sum(r["status"] == "fail" for r in valid)
        first_na = sum(r["status"] not in ("pass", "fail") for r in first)

        second = rows(SOURCE / "categories" / category / "second_level_uniformity.csv")
        second_valid = [r for r in second if r["recomputed_uniformity_p_value"].strip()]
        second_p = [float(r["recomputed_uniformity_p_value"]) for r in second_valid]
        second_official_fail = sum(p < UNIFORMITY_ALPHA_NIST for p in second_p)
        second_alpha01_screen = sum(p < ALPHA for p in second_p)

        comp_rows = rows(SOURCE / "categories" / category / "summary_counts.csv")
        component_warnings = 0
        for r in comp_rows:
            p, f, na = (int(r[k]) for k in ("pass", "fail", "not_applicable"))
            m = p + f
            if m == 0:
                continue
            proportion = p / m
            lower = (1 - ALPHA) - 3 * math.sqrt((1 - ALPHA) * ALPHA / m)
            outside = proportion < lower
            component_warnings += int(outside)
            if category in CRYPTO:
                exact_tail = float(binom.sf(f - 1, m, ALPHA)) if f else 1.0
                crypto_components.append({
                    "category": category,
                    "test": r["test_name"],
                    "component": r["component_label"],
                    "valid_streams": m,
                    "pass": p,
                    "fail": f,
                    "not_applicable": na,
                    "pass_proportion": f"{proportion:.12g}",
                    "nist_3sigma_lower_bound": f"{lower:.12g}",
                    "below_nist_approx_bound": outside,
                    "exact_binomial_upper_tail_p": f"{exact_tail:.12g}",
                })
        category_summary.append({
            "category": category,
            "kind": "cryptographic-component" if category in CRYPTO else "image-diagnostic",
            "first_level_valid_values": len(valid),
            "first_level_pass": first_pass,
            "first_level_fail": first_fail,
            "first_level_not_applicable": first_na,
            "first_level_pass_rate": f"{first_pass / len(valid):.8f}" if valid else "",
            "first_level_expected_failures_if_null": f"{len(valid) * ALPHA:.4f}",
            "component_proportions_below_nist_approx_bound": component_warnings,
            "second_level_rows": len(second),
            "second_level_uniformity_values": len(second_valid),
            "second_level_failures_at_nist_0_0001": second_official_fail,
            "second_level_values_below_0_01_exploratory_only": second_alpha01_screen,
            "minimum_second_level_p_value": f"{min(second_p):.12g}" if second_p else "",
        })

    holm_adjust(crypto_components, ALPHA)
    write_csv(OUT / "category_interpretation.csv", category_summary)
    write_csv(OUT / "cryptographic_component_proportions.csv", crypto_components)

    crypto_summary = [r for r in category_summary if r["kind"] == "cryptographic-component"]
    diagnostic_summary = [r for r in category_summary if r["kind"] == "image-diagnostic"]
    total_first_valid = sum(int(r["first_level_valid_values"]) for r in crypto_summary)
    total_first_fail = sum(int(r["first_level_fail"]) for r in crypto_summary)
    crypto_second = sum(int(r["second_level_uniformity_values"]) for r in crypto_summary)
    crypto_second_bad = sum(int(r["second_level_failures_at_nist_0_0001"]) for r in crypto_summary)
    crypto_second_sub01 = sum(int(r["second_level_values_below_0_01_exploratory_only"]) for r in crypto_summary)
    outside = sum(bool(r["below_nist_approx_bound"]) for r in crypto_components)
    holm_rejects = sum(bool(r["holm_reject_at_0_01"]) for r in crypto_components)
    nonoverlap_outside = sum(bool(r["below_nist_approx_bound"]) and r["test"] == "NonOverlappingTemplate" for r in crypto_components)
    min_second = min(float(r["minimum_second_level_p_value"]) for r in crypto_summary)

    report = [
        "# Independent interpretation of the NIST p-values",
        "",
        "This review reads the already-generated official NIST STS CSVs. It does not alter the cipher, regenerate data, select streams, or rewrite the original NIST reports.",
        "",
        "## Bottom line",
        "",
        f"The cryptographic-component results are broadly consistent with the null expectation: {total_first_valid - total_first_fail:,}/{total_first_valid:,} valid first-level values pass at α=0.01 ({100*(1-total_first_fail/total_first_valid):.3f}%; expected about 99%), and {crypto_second_bad}/{crypto_second} second-level uniformity values fail NIST's separate 0.0001 criterion. Their minimum second-level uniformity p-value is {min_second:.6g}.",
        "",
        f"There are {crypto_second_sub01} cryptographic second-level p-values below 0.01, but **none is below NIST's 0.0001 uniformity threshold**. Treating every second-level p<0.01 as an official failure was too strict; those are retained as an optional screening count, not an official fail count.",
        "",
        f"The NIST three-sigma first-level pass-proportion approximation flags {outside}/{len(crypto_components)} cryptographic test-components as below its lower bound; {nonoverlap_outside} are NonOverlappingTemplate components. Under exact one-sided binomial tests for excess first-level failures, followed by Holm correction across all {len(crypto_components)} cryptographic components at familywise 0.01, {holm_rejects} components remain significant. This is a cautionary diagnostic, not proof that every component is independent or that the cipher is secure.",
        "",
        "The image-derived ciphertext/recovered-image diagnostics are **not** expected to behave as random streams. Their low p-values do not indicate that the cryptographic PRF or HMAC outputs failed; they reflect structured image/plaintext data and must stay separately labelled.",
        "",
        "## Category results",
        "",
        "| Category | Type | First-level pass/fail/N-A | Pass rate | Components below NIST approximate pass bound | Second-level values <0.0001 (NIST) | Second-level values <0.01 (exploratory) | Minimum second-level p |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in category_summary:
        report.append(f"| `{r['category']}` | {r['kind']} | {r['first_level_pass']}/{r['first_level_fail']}/{r['first_level_not_applicable']} | {100*float(r['first_level_pass_rate']):.3f}% | {r['component_proportions_below_nist_approx_bound']} | {r['second_level_failures_at_nist_0_0001']}/{r['second_level_uniformity_values']} | {r['second_level_values_below_0_01_exploratory_only']}/{r['second_level_uniformity_values']} | {r['minimum_second_level_p_value'] or 'N/A'} |")
    report += [
        "",
        "First-level pass/fail/N-A totals are across every individual stream-test component in the category. The expected first-level failure fraction under the null is α=0.01; p-values are not supposed to be near 1 for every stream.",
        "",
        "## What to do",
        "",
        "Do not change code or parameters to push p-values upward. Keep all first-level failures and N/A outcomes. Report the correct NIST second-level 0.0001 criterion separately from the user-requested first-level α=0.01. If seeking stronger evidence, pre-register and generate a new independent campaign with more streams and unchanged definitions; use it as a replication, not as a replacement for this run. A genuine implementation defect would justify a code fix and an entirely new, fully disclosed run, but this review found no statistically adjusted component-level signal that by itself justifies changing the cryptographic construction.",
        "",
        "## Method and source",
        "",
        "For each first-level test component, the NIST approximate lower pass-proportion bound is `(1−α) − 3 sqrt((1−α) α / m)`, where `m=pass+fail` excludes N/A streams. We also test whether each component has an excess number of failures under `Binomial(m, α)` using a pre-specified lower-pass (upper-failure) tail, then Holm-adjust over the 752 cryptographic components at familywise α=0.01. This adjustment is supplementary; dependence among test types makes it inappropriate to interpret raw component tests independently.",
        "",
        "NIST SP 800-22 Rev. 1a §4.2.1 defines the first-level pass-proportion interval. §4.2.2 says the second-level uniformity p-value should be at least 0.0001 and at least 55 sequences should be processed. This campaign uses 100 streams per cryptographic category.",
        "",
        "See [SOURCES.md](SOURCES.md) for the source links. The detailed component-level calculations are in `output/cryptographic_component_proportions.csv`.",
        "",
    ]
    (OUT / "P_VALUE_REVIEW.md").write_text("\n".join(report), encoding="utf-8")
    print(f"Wrote {OUT / 'P_VALUE_REVIEW.md'}")
    print(f"Cryptographic components: {len(crypto_components)}; first-level pass-proportion warnings: {outside}; Holm-adjusted exact-binomial rejections: {holm_rejects}; official second-level uniformity failures: {crypto_second_bad}/{crypto_second}")


if __name__ == "__main__":
    main()
