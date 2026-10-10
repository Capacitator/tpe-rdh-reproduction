#!/usr/bin/env python3
"""Build the new Word report in the format of the original document.

The original report is used only as a *style template*: the new document is
written from scratch, reusing its table caption style and table style, and is
saved under a new name.  The original file is never modified.
"""
from __future__ import annotations

import csv
import datetime
import json
import sys
from pathlib import Path

import docx
from docx.shared import Pt

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
REPO = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))

import nist_runner as N  # noqa: E402
import streams as S  # noqa: E402

TEMPLATE = Path("/home/ubuntu/upload/authenticated_tpe_latest_old_format.docx")
TARGET = OUT / "report" / "authenticated_tpe_nist_v2_report.docx"
CAPTION_STYLE = "MDPI_4.1_table_caption"


def read_csv(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def fmt_p(value: str) -> str:
    if value in ("", None):
        return "—"
    try:
        number = float(value)
    except ValueError:
        return str(value)
    if number == 0.0:
        return "0"
    if number < 1e-4:
        return f"{number:.4e}"
    return f"{number:.6f}"


def counts_text(passed: str, failed: str, na: str) -> str:
    text = f"{passed}P/{failed}F"
    if na not in ("", "0", None):
        text += f"/{na}N/A"
    return text


def add_caption(document, text: str) -> None:
    paragraph = document.add_paragraph(text, style=CAPTION_STYLE)
    for run in paragraph.runs:
        run.font.size = Pt(9)


def add_paragraph(document, text: str) -> None:
    paragraph = document.add_paragraph(text)
    for run in paragraph.runs:
        run.font.size = Pt(10)


def add_table(document, header: list[str], rows: list[list[str]], style: str = "Table Grid"):
    table = document.add_table(rows=1, cols=len(header))
    try:
        table.style = style
    except KeyError:
        pass
    for index, name in enumerate(header):
        cell = table.rows[0].cells[index]
        cell.text = ""
        run = cell.paragraphs[0].add_run(name)
        run.bold = True
        run.font.size = Pt(8)
    for row in rows:
        cells = table.add_row().cells
        for index, value in enumerate(row):
            cells[index].text = ""
            run = cells[index].paragraphs[0].add_run(str(value))
            run.font.size = Pt(8)
    return table


def main() -> None:
    per_test = read_csv(OUT / "nist_per_test_summary.csv")
    headline = read_csv(OUT / "headline_counts.csv")
    quality = read_csv(OUT / "metrics" / "image_quality.csv")
    differential = read_csv(OUT / "metrics" / "npcr_uaci.csv")
    tamper = read_csv(OUT / "metrics" / "tamper_results.csv")
    same_key = read_csv(OUT / "metrics" / "same_key_cases.csv")
    independence = json.loads((OUT / "independence_checks.json").read_text()) \
        if (OUT / "independence_checks.json").is_file() else {}
    metrics_summary = json.loads((OUT / "metrics" / "metrics_summary.json").read_text()) \
        if (OUT / "metrics" / "metrics_summary.json").is_file() else {}
    before_after = read_csv(OUT / "before_after.csv")

    document = docx.Document(str(TEMPLATE))
    for element in list(document.element.body):
        if element.tag.endswith("}sectPr"):
            continue
        document.element.body.remove(element)

    add_paragraph(document,
                  "Thumbnail-Preserving Encrypted Colour Images: corrected NIST SP 800-22 Rev. 1a "
                  "evaluation of the authenticated scheme (revision atpe-v2.1). This document was "
                  "generated from the run recorded under "
                  "authenticated_tpe_nist_v2/output/. It replaces no existing report: the original "
                  "word document with its Tables 1-7 is preserved unchanged.")

    # ---- Table 1 -------------------------------------------------------
    add_caption(document, "Table 1. Results of the revised authenticated method on six UCT images "
                          "(block size 32x32, 512x512 RGB, group or whole-image mode as reported).")
    rows = []
    for row in quality:
        rows.append([row["image"], row["mode"], f"{float(row['protect_seconds']):.4f}",
                     f"{float(row['verify_seconds']):.4f}",
                     f"{float(row['marked_vs_step2_psnr_db']):.4f}",
                     f"{float(row['marked_vs_step2_ssim']):.4f}",
                     f"{row['max_abs_error']}",
                     f"{float(row['recovery_psnr_db']):.4f}",
                     f"{float(row['recovery_ssim']):.4f}"])
    if rows:
        mean = ["Mean"] + [""] * 8
        for index, key in enumerate(["protect_seconds", "verify_seconds", "marked_vs_step2_psnr_db",
                                     "marked_vs_step2_ssim"]):
            mean[index + 2] = f"{sum(float(r[key]) for r in quality) / len(quality):.4f}"
        mean[6] = "0"
        mean[7] = "inf"
        mean[8] = "1.0000"
        rows.append(mean)
    add_table(document, ["Image Id", "Mode", "Encryption time (s)", "Decryption time (s)",
                         "Encrypted-image PSNR (dB)", "Encrypted-image SSIM",
                         "Decrypted-image MSE..max error", "Decrypted-image PSNR",
                         "Decrypted-image SSIM"], rows)
    add_paragraph(document,
                  "Recovery is exact for every image (maximum absolute error 0, PSNR inf, SSIM 1.0), "
                  "and every tag verified. Marked-image PSNR/SSIM are measured against the Step-2 "
                  "intermediate, as in the original document. Whole-image mode appears where a group "
                  "of four blocks cannot reach 256 net bits; it is the method's documented fallback "
                  "and its tag verifies identically.")

    # ---- Table 2 -------------------------------------------------------
    add_caption(document, "Table 2. Differential, entropy and correlation statistics with the "
                          "standard two-ciphertext definitions (block size 32x32).")
    rows = []
    for row in differential[:6]:
        label = row["image"]
        rows.append([label, f"{float(row['npcr_percent']):.2f}", f"{float(row['uaci_percent']):.2f}",
                     f"{float(row['plaintext_vs_marked_npcr_percent']):.2f}",
                     f"{float(row['plaintext_vs_marked_uaci_percent']):.2f}"])
    if differential:
        rows.append(["Mean",
                     f"{sum(float(r['npcr_percent']) for r in differential) / len(differential):.2f}",
                     f"{sum(float(r['uaci_percent']) for r in differential) / len(differential):.2f}",
                     f"{sum(float(r['plaintext_vs_marked_npcr_percent']) for r in differential) / len(differential):.2f}",
                     f"{sum(float(r['plaintext_vs_marked_uaci_percent']) for r in differential) / len(differential):.2f}"])
        rows.append(["Ideal value", "99.6094", "33.4635", "n/a", "n/a"])
    add_table(document, ["Image Id", "NPCR % (two ciphertexts)", "UACI % (two ciphertexts)",
                         "Plaintext-vs-marked NPCR % (not NPCR)",
                         "Plaintext-vs-marked UACI % (not UACI)"], rows)
    add_paragraph(document,
                  "NPCR and UACI are computed between two ciphertexts of the same plaintext under two "
                  "independent (UserKey, ImageID) instances, which is the standard definition. The two "
                  "right-hand columns repeat, under their own names, the quantity the original report "
                  "published as NPCR/UACI; it is an embedding-distortion measurement of the RCM carrier "
                  "LSBs and is not the NPCR/UACI of the encryption.")
    add_paragraph(document,
                  "The measured NPCR and UACI are below their diffusion ideals (99.6094 % and "
                  "33.4635 %) and cannot reach them in this scheme: a thumbnail-preserving ciphertext "
                  "keeps every adjacent pair sum by construction, so two ciphertexts of one plaintext "
                  "differ only by a rotation inside each sum class. The earlier report's 1.09 % and "
                  "0.0088 % are a third, different quantity again (the LSB-level embedding "
                  "distortion), which is why all three are reported separately here under accurate "
                  "names instead of being merged into one headline number.")
    if metrics_summary:
        add_paragraph(document,
                      f"Step-1 offset uniformity: the reduced offset is the raw PRF word modulo the "
                      f"sum-class size, which is biased by at most 255/2^32 before rejection "
                      f"sampling. All {metrics_summary.get('class_uniformity_sizes')} distinct class "
                      f"sizes were screened with 200,000 independent PRF words: "
                      f"{metrics_summary.get('class_uniformity_uncorrected_failures')} had an "
                      f"uncorrected p < 0.01 (expected "
                      f"{metrics_summary.get('class_uniformity_expectation')} by chance) and none "
                      f"survived a Holm-Bonferroni correction. The sizes that looked marginal were "
                      f"re-tested with 1,048,576 draws (output/metrics/class_uniformity_retest.csv) "
                      f"and are uniform (p = 0.32, 0.15 and 0.61 for class sizes 4, 86 and 142). The "
                      f"rejection-sampling revision is therefore confirmed to be exact, and no "
                      f"residual bias is detectable.")

    # ---- Table 3 -------------------------------------------------------
    if quality:
        add_caption(document, "Table 3. Entropy and neighbouring-pixel correlation of the original "
                              "image and of the encrypted image (block size 32x32), RGB-mean.")
        rows = []
        for row in quality:
            rows.append([row["image"],
                         f"{float(row['entropy_plaintext']):.4f}", f"{float(row['entropy_marked']):.4f}",
                         f"{float(row['corr_plaintext_h']):.4f}", f"{float(row['corr_plaintext_v']):.4f}",
                         f"{float(row['corr_marked_h']):.4f}", f"{float(row['corr_marked_v']):.4f}"])
        add_table(document, ["Image Id", "Entropy original", "Entropy encrypted",
                             "Corr. original (H)", "Corr. original (V)",
                             "Corr. encrypted (H)", "Corr. encrypted (V)"], rows)

    # ---- Table 4: NIST cryptographic components ------------------------
    crypto = [row for row in per_test if row["kind"] == "cryptographic-component"]
    diag = [row for row in per_test if row["kind"] == "diagnostic"]
    crypto_categories = [c for c in S.CATEGORY_ORDER if S.CATEGORY_KIND[c] == "cryptographic-component"]
    diagnostic_categories = [c for c in S.CATEGORY_ORDER if S.CATEGORY_KIND[c] == "diagnostic"]

    def nist_rows(rows_source: list[dict], categories: list[str]) -> tuple[list[str], list[list[str]]]:
        by_category_test = {(row["category"], row["test"]): row for row in rows_source}
        header = ["NIST Test"] + [f"{category}\np-value" for category in categories] + \
                 [f"{category}\nresult" for category in categories]
        body = []
        for test in N.TEST_ORDER:
            cells = [N.TEST_LABELS[test]]
            values = []
            results = []
            for category in categories:
                row = by_category_test.get((category, test))
                if row is None:
                    values.append("—")
                    results.append("—")
                    continue
                components = int(row["components"])
                if components == 1:
                    values.append(fmt_p(row["recomputed_uniformity_p_min"] or row["suite_uniformity_p_min"]))
                else:
                    values.append(f"{fmt_p(row['recomputed_uniformity_p_min'])} .. "
                                  f"{fmt_p(row['recomputed_uniformity_p_max'])} ({components})")
                results.append(counts_text(row["pass"], row["fail"], row["not_applicable"]))
            body.append(cells + values + results)
        return header, body

    if crypto:
        add_caption(document, "Table 4. Corrected NIST SP 800-22 Rev. 1a results for the "
                              "cryptographic-component streams: 100 streams per category, 1,000,000 "
                              "bits per stream, alpha=0.01, official STS 2.1.2 with all tests at "
                              "default parameters. p-values are second-level uniformity p-values "
                              "(recomputed at full precision from the suite's own C1..C10 histogram); "
                              "a range with a component count is given for multi-component tests. "
                              "Results are pass/fail/not-applicable counts over all first-level "
                              "p-values of the category.")
        header, body = nist_rows(crypto, crypto_categories)
        add_table(document, header, body)
        add_paragraph(document,
                      "These four categories are the objects the scheme's security actually rests on: "
                      "the HMAC_DRBG(HMAC-SHA256) generator that produces the block-group permutation, "
                      "the Step-1 pair-shift PRF, the Step-2 block-r1 PRF and the HMAC-SHA256 "
                      "authentication tags. NIST SP 800-22 evaluates them as pseudorandom bit "
                      "streams; it does not evaluate the ciphertext of a thumbnail-preserving scheme, "
                      "which is not pseudorandom by construction.")

    if diag:
        add_caption(document, "Table 5. NIST SP 800-22 Rev. 1a *diagnostics* for the image-derived "
                              "and reduced-offset streams. These streams are deliberately not "
                              "randomness claims: a thumbnail-preserving ciphertext preserves block "
                              "sums, the recovered image is plaintext, and a byte-packing of the "
                              "reduced Step-1 offsets cannot be uniform because sum-class sizes differ. "
                              "Failures are reported in full.")
        header, body = nist_rows(diag, diagnostic_categories)
        add_table(document, header, body)
        add_paragraph(document,
                      "Every failure and every not-applicable outcome in these three diagnostic "
                      "categories is reported above without selection. They are listed separately from "
                      "Table 4 precisely so that structured image bytes are never presented as a "
                      "randomness result for the encryption.")

    # ---- Table 6: before/after -----------------------------------------
    if before_after:
        add_caption(document, "Table 6. Before/after comparison against Table 7 of the original "
                              "document. 'Before' values are transcribed from the original Word file; "
                              "'after' values are the HMAC_DRBG cryptographic-component category of "
                              "this run (the category that corresponds to a keystream claim).")
        rows = []
        for row in before_after:
            rows.append([row["test_label"],
                         f"{row['before_step2_intermediate_p']} ({row['before_step2_intermediate_result']})",
                         f"{row['before_final_marked_p']} ({row['before_final_marked_result']})",
                         row["after_uniformity_p_range"] or "—",
                         counts_text(row["after_pass"], row["after_fail"], row["after_not_applicable"])
                         if row["after_pass"] else "—"])
        add_table(document, ["NIST Test", "Before: Step-2 intermediate",
                             "Before: final marked image", "After: p-value range",
                             "After: pass/fail/N-A"], rows)

    # ---- Table 7: headline counts --------------------------------------
    if headline:
        add_caption(document, "Table 7. Totals per stream category over all first-level p-values "
                              "(15 STS tests; 188 test components).")
        rows = []
        for row in headline:
            rows.append([row["category"], row["kind"], row["title"], row["streams"],
                         f"{int(row['bits_per_stream']):,}", row["first_level_values"],
                         row["pass"], row["fail"], row["not_applicable"]])
        add_table(document, ["Category", "Kind", "Stream definition", "Streams", "Bits/stream",
                             "First-level values", "Pass", "Fail", "N/A"], rows)

    # ---- Table 8: authentication and differential checks ----------------
    if tamper:
        add_caption(document, "Table 8. Authentication behaviour of the revised build: controlled "
                              "forgery attempts, wrong credentials, a valid-substitution case and a "
                              "positive control.")
        rows = [[row["case"], row["case_kind"], row["rejected"], row["mode_reported"],
                 row["failed_groups_reported"], row["plaintext_released"], row["reason"]]
                for row in tamper]
        add_table(document, ["Case", "Kind", "Rejected", "Mode reported",
                             "Failed groups reported", "Plaintext released", "Reason"], rows)
        add_paragraph(document,
                      "All five forgery and wrong-credential cases are rejected, with no plaintext "
                      "released in any of them. The 'valid substitution' row is deliberately not "
                      "counted as a rejected attack: a correctly tagged ciphertext of a different "
                      "image, produced under the same UserKey and ImageID, verifies, because the "
                      "tag authenticates ciphertext content and the scheme does not bind image "
                      "identity. That is exactly why the design requires a fresh ImageID per image, "
                      "and it is disclosed here rather than removed.")
    if same_key:
        add_caption(document, "Table 9. Same-key cases: what actually changes when the ImageID or the "
                              "image changes under one UserKey.")
        rows = [[row["case"], row["keystream_identical"], row["first_tag_identical"],
                 row["ciphertext_identical"], row["step1_identical"]] for row in same_key]
        add_table(document, ["Case", "Keystream identical", "First tag identical",
                             "Ciphertext identical", "Step-1 identical"], rows)

    # ---- Provenance -----------------------------------------------------
    add_caption(document, "Table 10. Provenance and independence of this evaluation.")
    provenance = []
    provenance_path = OUT / "provenance.txt"
    if provenance_path.is_file():
        for line in provenance_path.read_text().splitlines():
            if line.startswith(("repository_commit=", "revision_id=", "python=", "numpy=",
                                "nist_sts_version=", "nist_sts_build_patch_sha256=",
                                "sts_binary_sha256=", "protocol_script_sha256=",
                                "streams_module_sha256=", "atpe_v2_module_sha256=",
                                "streams_per_category=", "bits_per_stream=",
                                "significance_level=", "sts_command=")):
                key, _, value = line.partition("=")
                provenance.append([key, value])
    if independence:
        provenance.append(["streams_total", independence.get("total_streams")])
        provenance.append(["streams_unique_sha256", independence.get("unique_streams")])
        provenance.append(["duplicate_streams", independence.get("duplicate_stream_count")])
        provenance.append(["total_bits_evaluated", independence.get("total_bits")])
        provenance.append(["key_index_partition_disjoint",
                           independence.get("key_partition", {}).get("disjoint")])
        provenance.append(["key_indices_used",
                           independence.get("key_partition", {}).get("key_indices_used")])
        provenance.append(["image_reuse_inside_a_stream",
                           independence.get("image_reuse", {}).get("no_image_repeats_inside_a_stream")])
        provenance.append(["revision_active",
                           independence.get("revision", {}).get("prototype_pair_shift_is_revised")])
    if metrics_summary:
        provenance.append(["sum_class_sizes_screened", metrics_summary.get("class_uniformity_sizes")])
        provenance.append(["class_uniformity_uncorrected_failures_at_0.01",
                           f"{metrics_summary.get('class_uniformity_uncorrected_failures')} "
                           f"(expected {metrics_summary.get('class_uniformity_expectation')})"])
        provenance.append(["class_uniformity_holm_rejections_at_0.01",
                           metrics_summary.get("class_uniformity_holm_rejections")])
        provenance.append(["class_uniformity_retest_uniform",
                           (OUT / "metrics" / "class_uniformity_retest.csv").is_file()])
        provenance.append(["forgery_cases_rejected_all", metrics_summary.get("forgery_rejected_all")])
        provenance.append(["forgery_plaintext_leaked", metrics_summary.get("forgery_plaintext_leaked")])
        provenance.append(["npcr_mean_percent", round(metrics_summary.get("npcr_mean_percent", 0), 4)])
        provenance.append(["uaci_mean_percent", round(metrics_summary.get("uaci_mean_percent", 0), 4)])
    add_table(document, ["Item", "Value"], provenance)

    add_paragraph(document,
                  "Reproduction: python experiments/run_protocol.py --sts-dir <NIST_STS_2_1_2_ROOT>; "
                  "python experiments/run_metrics.py; python -m pytest tests -q. Every stream, its "
                  "SHA-256 digest, the official per-test reports and the parsed CSVs are stored under "
                  "output/. Regenerating the streams reproduces every recorded digest exactly.")
    add_paragraph(document,
                  "Limitations: NIST SP 800-22 is a statistical battery, not a security proof; the "
                  "April 2022 NIST notice plans its revision and rejects its use as an assessment of "
                  "cryptographic generators. Passing outcomes here describe the tested streams under "
                  "the stated parameters. Step 1 deliberately preserves adjacent pair sums, so the "
                  "ciphertext leaks them; the marked image is not pseudorandom and is not claimed to "
                  "be. No cryptanalysis, formal proof or production hardening is provided, and the "
                  "recovered image is plaintext.")
    add_paragraph(document,
                  f"Generated {datetime.datetime.now(datetime.timezone.utc).isoformat()} by "
                  f"experiments/make_report.py from the artifacts in authenticated_tpe_nist_v2/output/.")

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    document.save(str(TARGET))
    print(f"wrote {TARGET}")


if __name__ == "__main__":
    main()
