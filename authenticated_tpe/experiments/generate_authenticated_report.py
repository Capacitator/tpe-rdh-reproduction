"""Regenerate authenticated-TPE reports from checked-in experiment artifacts."""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "authenticated_tpe"
REPORT = PROJECT / "reports/AUTHENTICATED_TPE_REPORT.md"
SUMMARY = PROJECT / "reports/EXECUTIVE_SUMMARY.md"


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def run(command: list[str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise RuntimeError(result.stdout)
    return result.stdout.strip()


def test_result() -> str:
    output = run([sys.executable, "-m", "pytest", "tests", "-q"], PROJECT)
    match = re.search(r"(\d+ passed[^\n]*)", output)
    if not match:
        raise RuntimeError(f"Could not parse pytest result:\n{output}")
    return match.group(1)


def provenance_map() -> dict[str, str]:
    return dict(line.split("=", 1) for line in (PROJECT / "output/provenance.txt").read_text().splitlines() if "=" in line)


def table(data: list[dict[str, str]], columns: list[tuple[str, str]]) -> str:
    lines = ["| " + " | ".join(label for label, _ in columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
    for row in data:
        lines.append("| " + " | ".join(row[key] for _, key in columns) + " |")
    return "\n".join(lines)


def generated_statistics() -> str:
    out = ["## Authenticated-TPE statistical and differential evaluation", ""]
    plain_path = PROJECT / "output/npcr_uaci_results.csv"
    key_path = PROJECT / "output/key_sensitivity_npcr_uaci.csv"
    if plain_path.exists() and key_path.exists():
        plain, key = rows(plain_path), rows(key_path)
        out.extend([
            "### Plaintext-difference NPCR/UACI (fixed ImageID)", "",
            "For each of the six UCT images, protect the clean input and its modified copy under the same public test UserKey and fixed deterministic test ImageID. Modify only the top-left R-channel sample in each 32×32 block by +1, or −1 if it is 255, matching the original project's differential perturbation convention at the authenticated method's specified block size. Both outputs must authenticate and recover exactly. Per-channel R/G/B and pooled RGB rows are recorded per image and for the six-image aggregate.", "",
            "Formulas: NPCR = 100 × count(Aᵢ ≠ Bᵢ) / N; UACI = 100 × Σ|int16(Aᵢ)−int16(Bᵢ)| / (255 × N). For a channel N=H×W; for pooled RGB N=3×H×W. These follow the original project's per-channel formulas and pooled RGB key-sensitivity formula.", "",
            table(plain, [("Experiment", "experiment"), ("Image", "image"), ("Channel", "channel"), ("NPCR %", "npcr_percent"), ("UACI %", "uaci_percent"), ("Base exact", "base_authenticates_and_recovers"), ("Modified exact", "modified_authenticates_and_recovers")]), "",
            "### One-bit key sensitivity (fixed ImageID)", "",
            "Keep the same image, fixed ImageID and payload-free setup; flip one bit by XORing byte 0 of the UserKey with 0x01, matching the original project's key-sensitivity convention. Both outputs must authenticate and recover under their corresponding keys.", "",
            table(key, [("Experiment", "experiment"), ("Image", "image"), ("Channel", "channel"), ("NPCR %", "npcr_percent"), ("UACI %", "uaci_percent"), ("Base exact", "base_authenticates_and_recovers"), ("Flipped key exact", "flipped_key_authenticates_and_recovers")]), "",
            "NPCR and UACI are empirical differential metrics, not proofs of cryptographic security. CSVs and test conditions: `authenticated_tpe/output/npcr_uaci_results.csv`, `key_sensitivity_npcr_uaci.csv`, and `statistical_provenance.txt`.", "",
        ])
    else:
        out.extend(["Not reproduced: required original notebook/data/parameter was unavailable. NPCR/UACI outputs have not yet been generated.", ""])

    reuse_path = PROJECT / "output/same_key_different_image.csv"
    if reuse_path.exists():
        reuse = rows(reuse_path)
        out.extend(["### Same-key/different-image behavior", "",
                    "The fixed-ImageID variant holds key and ImageID constant for airplane and baboon, isolating image dependence. The separate image-specific deterministic-ID variant follows the paper's private ImageID model; because both image and ImageID change, that variant alone cannot establish image dependence. Only ImageID digests are shown.", "",
                    table(reuse, [("Variant", "variant"), ("Image", "image"), ("Image file SHA-256", "source_image_file_sha256"), ("ImageID SHA-256", "image_id_sha256"), ("Step-1 SHA-256", "step1_sha256"), ("Step-2 SHA-256", "step2_sha256"), ("Final SHA-256", "final_marked_sha256"), ("Image differs", "image_differs_from_other"), ("ID differs", "image_id_differs_from_other"), ("Step 1 differs", "step1_differs_from_other"), ("Step 2 differs", "step2_differs_from_other"), ("Final differs", "final_differs_from_other"), ("Exact recovery", "exact_recovery")]), ""])
    consistency_path = PROJECT / "output/consistency_hashes.csv"
    if consistency_path.exists():
        consistency = rows(consistency_path)
        out.extend(["### Same-image consistency and hashes", "",
                    table(consistency, [("Case", "case"), ("Image", "image"), ("ImageID SHA-256", "image_id_sha256"), ("Step-1 SHA-256", "step1_sha256"), ("Step-2 SHA-256", "step2_sha256"), ("Final marked SHA-256", "final_marked_sha256"), ("Recovered SHA-256", "recovered_image_sha256"), ("Repeat identical", "identical_repeat"), ("Different ID changes output", "different_image_id_changes_output"), ("ID absent from marked pixels", "image_id_bytes_absent_from_marked_pixels"), ("Exact recovery", "clean_exact_recovery")]), ""])

    nist_path = PROJECT / "output/nist_sp800_22/results.csv"
    if nist_path.exists():
        nist = rows(nist_path)
        categories = list(dict.fromkeys(row["category"] for row in nist))
        out.extend(["### NIST SP 800-22 Rev. 1a", "",
                    "The official STS 2.1.2 workflow and parameters match the original project's stream count, length, alpha, image order, key fixtures, packing, selected tests, special settings, and pass/fail/not-applicable interpretation. Category `step2_intermediate` is the keyed Step-2 RGB image before RCM tag embedding; it is an image intermediate, **not a chaotic sequence**. `final_marked_rgb` is the final RCM-marked RGB output. Both are row-major RGB uint8 bytes, serialized MSB-first and truncated at the stated length.", "",
                    "Complete per-test component outcomes (pass / fail / not-applicable):", "",
                    "| Test | Step-2 intermediate | Final marked RGB |", "|---|---:|---:|"])
        for test in dict.fromkeys(row["test_name"] for row in nist):
            values = []
            for category in categories:
                subset = [row for row in nist if row["test_name"] == test and row["category"] == category]
                values.append(" / ".join(str(sum(row["status"] == status for row in subset)) for status in ("pass", "fail", "not-applicable")))
            out.append(f"| {test} | {values[0]} | {values[1]} |")
        for category in categories:
            subset = [row for row in nist if row["category"] == category]
            counts = [sum(row["status"] == status for row in subset) for status in ("pass", "fail", "not-applicable")]
            out.append(f"\n**{category} component totals:** pass={counts[0]}, fail={counts[1]}, not-applicable={counts[2]}.")
        out.extend(["", "No single overall NIST pass is computed. SP 800-22, NPCR, and UACI are statistical diagnostics, not proofs of security. Per-stream source hashes, exact command, test setup, and script hashes are in `authenticated_tpe/output/nist_sp800_22/provenance.txt`.", ""])
    else:
        out.extend(["NIST result files have not been generated. Not reproduced: required original notebook/data/parameter was unavailable.", ""])
    return "\n".join(out) + "\n"


def generated_sections(tests: str, tamper_script: str) -> str:
    clean = rows(PROJECT / "output/clean_authentication_results.csv")
    attacks = rows(PROJECT / "output/tamper_results.csv")
    capacity = rows(PROJECT / "output/capacity_results.csv")
    p = provenance_map()
    shared_path = p["shared_input_dependency"].split(";", 1)[0].strip()
    passed = sum(r["verified"].lower() == "true" and r["exact_recovery"].lower() == "true" for r in clean)
    attacked = sum(r["verification_rejected"].lower() == "true" for r in attacks)
    no_plaintext = sum(r["plaintext_released"].lower() == "false" for r in attacks)
    group_rows = [r for r in capacity if r["mode"] == "group"]
    fallback = [r for r in capacity if r["mode"] == "whole-image"]
    group_peak = [int(r["min_group_peak_net_bits"]) for r in group_rows]
    whole_capacity = [int(r["whole_image_net_capacity_bits"]) for r in group_rows]
    clean = clean
    out = [
        "## Clean-image authentication results", "",
        table(clean, [("Image", "image"), ("Mode", "mode"), ("Tags", "embedded_tags"), ("Verified", "verified"), ("Exact recovery", "exact_recovery"), ("Pairs used", "pairs_used"), ("Marked vs Step-2 PSNR (dB)", "marked_vs_step2_psnr_db"), ("Protect (s)", "protect_seconds"), ("Verify (s)", "verify_seconds")]), "",
        f"The checked-in CSV contains {len(clean)} clean cases; {passed}/{len(clean)} verify and recover exactly. These include the six UCT image cases; modes, tag counts, exact per-image values and timings above are read directly from `output/clean_authentication_results.csv`. Marked-image PSNR compares the marked image with the Step-2 image before RCM marking and is not a security metric.", "",
        "## Tampering and authentication failures", "",
        table(attacks, [("Attack", "attack"), ("Rejected", "verification_rejected"), ("Failed groups", "failed_groups_reported"), ("Plaintext released", "plaintext_released")]), "",
        f"The artifact records {attacked}/{len(attacks)} attacks rejected and {no_plaintext}/{len(attacks)} with no plaintext released. Wrong-key, wrong-ImageID, replacement, same-channel block-swap, and cross-channel block-swap outcomes and failed-group counts are shown in the CSV-derived table. Group localization is only reported where verification identifies affected groups; zero means no failed group was attributable in these cases.", "",
        "## Capacity and operating modes", "",
        table(capacity, [("Fixture", "image"), ("Mode", "mode"), ("Groups at target", "groups_capacity_at_least_256"), ("Minimum group peak (bits)", "min_group_peak_net_bits"), ("Whole-image capacity (bits)", "whole_image_net_capacity_bits")]), "",
        f"For the {len(group_rows)} group-mode natural-image cases, minimum group peak capacity ranges from {min(group_peak)} to {max(group_peak)} bits; whole-image net capacity ranges from {min(whole_capacity)} to {max(whole_capacity)} bits. The separate constructed fixture exercises whole-image fallback: {fallback[0]['groups_capacity_at_least_256']} groups meet the group threshold, and its whole-image capacity is {fallback[0]['whole_image_net_capacity_bits']} bits. Capacity details are in `output/capacity_results.csv`.", "",
        "## Tests, independent check, and provenance", "",
        f"Authenticated-project test command `python -m pytest tests -q` from `authenticated_tpe/` passed **{tests}**. The independent script `python experiments/check_authenticated_tpe_tampering.py` exited successfully; recorded output: `{tamper_script.replace(chr(10), '; ').replace('`', '')}`.", "",
        "### Artifact provenance", "",
        f"- Branch `{git('branch', '--show-current')}`; report source commit `{git('rev-parse', 'HEAD')}`; worktree at report generation: `{'dirty' if git('status', '--porcelain') else 'clean'}`.",
        f"- Artifact-generating source commit: `{p.get('source_commit', 'unavailable')}`; artifact source worktree state: `{p.get('source_worktree', 'unavailable')}`.",
        f"- Runtime: Python {sys.version.split()[0]}; NumPy {importlib.metadata.version('numpy')}; Pillow {importlib.metadata.version('pillow')}; pytest {importlib.metadata.version('pytest')}.",
        f"- Input paths: `{shared_path}/{{airplane,baboon,couple,girl,lena,peppers}}.tif` (read-only shared UCT fixtures).",
        "- Input image SHA-256 values:", "",
    ]
    hashes = dict(piece.split(":", 1) for piece in p["input_uct_colour_sha256"].split(","))
    out.extend(f"  - `{name}`: `{value}`" for name, value in hashes.items())
    out.extend([
        f"- Specification SHA-256: `{p['specification_sha256']}`.",
        "- Public deterministic test fixtures only; no secret key or private production ImageID is reproduced here.",
        "- Report-generation script: `authenticated_tpe/experiments/generate_authenticated_report.py`; exact command: `.venv/bin/python authenticated_tpe/experiments/generate_authenticated_report.py` from repository root.",
        "- Source/artifact paths: `authenticated_tpe/src/`, `tests/`, `experiments/`, `docs/`, and `output/`; measurements are from `output/clean_authentication_results.csv`, `tamper_results.csv`, `capacity_results.csv`, and `provenance.txt`.",
        "- Statistical experiment provenance and script hashes: `authenticated_tpe/output/statistical_provenance.txt` and `authenticated_tpe/output/nist_sp800_22/provenance.txt`.",
        "", "## Reproduction status and limitations", "",
        "The implementation reconstructs the paper description using explicit documented conventions. The professor's external notebook and full attack study were unavailable. The reported six UCT fixtures, constructed fallback fixture, finite attack set, authenticated-TPE statistical and differential evaluation, and NIST SP 800-22 diagnostics are prototype evaluation, not a formal security proof or independent cryptanalysis. Lossless image handling, UserKey secrecy, and fresh private production ImageIDs remain operational requirements.",
    ])
    return "\n".join(out) + "\n"


def main() -> None:
    tests = test_result()
    tamper_script = run([sys.executable, "experiments/check_authenticated_tpe_tampering.py"], PROJECT)
    old = REPORT.read_text(encoding="utf-8")
    title = old.split("## Executive findings", 1)[0]
    method = old.split("## Method and scope", 1)[1].split("## Clean-image authentication results", 1)[0]
    clean = rows(PROJECT / "output/clean_authentication_results.csv")
    attacks = rows(PROJECT / "output/tamper_results.csv")
    natural = [r for r in clean if r["image"] != "constructed_capacity_fallback_fixture"]
    verified_natural = sum(r["verified"].lower() == "true" and r["exact_recovery"].lower() == "true" for r in natural)
    rejected_without_plaintext = sum(r["verification_rejected"].lower() == "true" and r["plaintext_released"].lower() == "false" for r in attacks)
    executive = ("## Executive findings\n\n"
                 "This project is a separate prototype of the professor-supplied reversible block-group authentication method. It combines pair-sum-preserving two-pixel encryption, reversible contrast mapping (RCM), and HMAC-SHA256 tags. It is independently implemented and does not import the original chaotic TPE/RDH pipeline.\n\n"
                 f"Checked-in outputs record {verified_natural}/{len(natural)} natural UCT clean cases with successful verification and exact recovery, and {rejected_without_plaintext}/{len(attacks)} controlled tampering or credential cases rejected without plaintext. A constructed capacity fixture exercises whole-image fallback. These observations cover the recorded cases and are not a formal security proof or independent cryptanalysis.\n\n")
    prefix = title + executive + "## Method and scope" + method
    suffix = old.split("\n## Reproduction\n", 1)[1]
    suffix = suffix.split("\n## Clean-image authentication results", 1)[0]
    REPORT.write_text(prefix + generated_sections(tests, tamper_script) + "\n" + generated_statistics() + "\n## Reproduction\n" + suffix.lstrip("\n"), encoding="utf-8")
    capacity = rows(PROJECT / "output/capacity_results.csv")
    verified = sum(r["verified"].lower() == "true" and r["exact_recovery"].lower() == "true" for r in clean)
    rejected = sum(r["verification_rejected"].lower() == "true" and r["plaintext_released"].lower() == "false" for r in attacks)
    fallback_ok = any(r["mode"] == "whole-image" and r["whole_image_capacity_at_least_256"].lower() == "true" for r in capacity)
    summary = f"""# Executive summary: authenticated-TPE prototype

## Implemented and tested

The project implements the professor-specific reversible block-group authentication method using pair-sum-preserving TPE, RCM, HMAC-SHA256, and four-block groups. It is an independent implementation, not an extension of the original chaotic algorithm.

- Authenticated-project tests: **{tests}**.
- Clean artifact cases that both verify and recover exactly: **{verified}/{len(clean)}**.
- Tamper/credential cases rejected without plaintext: **{rejected}/{len(attacks)}**.
- Whole-image fallback has a sufficient recorded capacity: **{fallback_ok}**.
- The independent tampering script passed.

## Limitations and final status

The implementation uses documented conventions and deterministic public fixtures. A constructed case exercises fallback; the professor's external notebook and full attack study were unavailable. This is finite prototype evaluation, not a formal security proof.

> The paper-specific authenticated-TPE prototype passes the documented clean-recovery, authentication, tamper-rejection, wrong-key, wrong-ImageID, and whole-image-fallback tests under the stated parameters. These finite prototype tests do not constitute a formal security proof or complete reproduction of unavailable external attack notebooks.

Final status: documented prototype validation complete; the unavailable external notebook and attack study were not reproduced.

## Provenance

Branch `{git('branch', '--show-current')}`, source commit `{git('rev-parse', 'HEAD')}`; report-generation worktree state: `{'dirty' if git('status', '--porcelain') else 'clean'}`. See [the detailed report](AUTHENTICATED_TPE_REPORT.md) for dependencies, input hashes, exact commands, artifact paths, and specification hash.
"""
    SUMMARY.write_text(summary, encoding="utf-8")


if __name__ == "__main__":
    main()
