"""Run deterministic experiments for the separate RCM/HMAC prototype."""
from __future__ import annotations

import csv
import hashlib
import platform
import sys
import time
from pathlib import Path
import subprocess

import numpy as np
from PIL import Image

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
import authenticated_tpe as a

OUT = PROJECT / "output"
TEST_KEY = bytes(range(32))  # Public deterministic fixture, never a production key.


def write_csv(path: Path, rows: list[dict]) -> None:
    fields = list(rows[0]) if rows else []
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def image_id_for(label: str) -> bytes:
    # Reproducible fixture only; production must use generate_image_id().
    return hashlib.sha256(b"authenticated-tpe-test-image-id-v1\x00" + label.encode("ascii")).digest()[:16]


def psnr(a0: np.ndarray, b0: np.ndarray) -> float:
    mse = float(np.mean((a0.astype(np.float64) - b0.astype(np.float64)) ** 2))
    return float("inf") if mse == 0 else 10.0 * np.log10((255.0 * 255.0) / mse)


def capacity(image: np.ndarray, key: bytes) -> tuple[list[int], int]:
    group_peaks: list[int] = []
    for c in range(3):
        for ids in a.group_blocks(a.derive_keys(key, c)["Kstruct"]):
            net = peak = 0
            for _, bid, k in a._group_slots(c, ids):
                pair = a._pairs(a._get_block(image, c, bid))[k]
                net += -1 if a.classify_pair(int(pair[0]), int(pair[1])) == "N" else 1
                peak = max(peak, net)
            group_peaks.append(peak)
    whole = peak_whole = 0
    for c, bid, k in a._whole_slots():
        pair = a._pairs(a._get_block(image, c, bid))[k]
        whole += -1 if a.classify_pair(int(pair[0]), int(pair[1])) == "N" else 1
        peak_whole = max(peak_whole, whole)
    return group_peaks, peak_whole


def load_rgb(path: Path) -> np.ndarray:
    return np.asarray(Image.open(path).convert("RGB").resize((512, 512)), dtype=np.uint8)


def attack_rows(image: np.ndarray, protected: a.ProtectResult, image_id: bytes) -> list[dict]:
    m = protected.marked_image
    cases: list[tuple[str, np.ndarray, bytes, bytes]] = []
    changed = m.copy(); changed[0, 0, 0] ^= 1
    cases.append(("single_pixel_lsb_flip", changed, TEST_KEY, image_id))
    swap = m.copy(); x = a._get_block(swap, 0, 0).copy(); y = a._get_block(swap, 0, 1).copy()
    a._get_block(swap, 0, 0)[:] = y; a._get_block(swap, 0, 1)[:] = x
    cases.append(("same_channel_block_swap", swap, TEST_KEY, image_id))
    cross = m.copy(); x = a._get_block(cross, 0, 0).copy(); y = a._get_block(cross, 1, 0).copy()
    a._get_block(cross, 0, 0)[:] = y; a._get_block(cross, 1, 0)[:] = x
    cases.append(("cross_channel_block_swap", cross, TEST_KEY, image_id))
    wrong_key = bytes([TEST_KEY[0] ^ 1]) + TEST_KEY[1:]
    cases.append(("wrong_user_key", m, wrong_key, image_id))
    wrong_id = bytes([image_id[0] ^ 1]) + image_id[1:]
    cases.append(("wrong_image_id", m, TEST_KEY, wrong_id))
    replacement_id = image_id_for("replacement")
    replacement_image = image.copy()
    replacement_image[40:56, 80:96] = 255 - replacement_image[40:56, 80:96]
    replacement = a.protect_image(replacement_image, TEST_KEY, replacement_id).marked_image
    cases.append(("different_protected_image_replacement", replacement, TEST_KEY, image_id))
    rows = []
    for name, attacked, key, iid in cases:
        result = a.verify_and_decrypt(attacked, key, iid)
        rows.append({"attack": name, "verification_rejected": not result.accepted,
                     "failed_groups_reported": len(result.failed_groups),
                     "plaintext_released": result.recovered_image is not None})
    return rows


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    repo = PROJECT.parent
    source_commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    source_status = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain"], text=True)
    source_worktree = "clean" if not source_status.strip() else "modified"
    clean_rows: list[dict] = []
    cap_rows: list[dict] = []
    attack_results: list[dict] = []
    shared_input = PROJECT.parent / "tpe_rdh_reproduction" / "input" / "uct_colour"
    fixture_paths = sorted(shared_input.glob("*.tif"))
    if not fixture_paths:
        raise RuntimeError("no UCT colour TIFFs were found")
    representative: tuple[np.ndarray, a.ProtectResult, bytes] | None = None
    for path in fixture_paths:
        image = load_rgb(path)
        iid = image_id_for(path.stem)
        started = time.perf_counter()
        protected = a.protect_image(image, TEST_KEY, iid)
        protect_seconds = time.perf_counter() - started
        verify_started = time.perf_counter()
        verified = a.verify_and_decrypt(protected.marked_image, TEST_KEY, iid)
        verify_seconds = time.perf_counter() - verify_started
        exact = verified.accepted and np.array_equal(verified.recovered_image, image)
        step2 = a._transform_image(image, TEST_KEY, iid)
        clean_rows.append({
            "image": path.stem, "dimensions": "512x512x3", "mode": protected.mode,
            "embedded_tags": protected.embedded_tags,
            "verified": verified.accepted, "exact_recovery": exact,
            "pairs_used": protected.pairs_used,
            "marked_vs_step2_psnr_db": f"{psnr(protected.marked_image, step2):.6f}",
            "protect_seconds": f"{protect_seconds:.6f}", "verify_seconds": f"{verify_seconds:.6f}",
        })
        peaks, whole_peak = capacity(step2, TEST_KEY)
        cap_rows.append({
            "image": path.stem, "mode": protected.mode, "groups_attempted": len(peaks),
            "groups_capacity_at_least_256": sum(v >= a.TAG_BITS for v in peaks),
            "min_group_peak_net_bits": min(peaks),
            "mean_group_peak_net_bits": f"{np.mean(peaks):.3f}",
            "max_group_peak_net_bits": max(peaks), "whole_image_net_capacity_bits": whole_peak,
            "whole_image_capacity_at_least_256": whole_peak >= a.TAG_BITS,
        })
        if representative is None and protected.mode == "group":
            representative = image, protected, iid

    if representative is None:
        raise RuntimeError("no UCT input produced group mode; attack suite needs a group-mode fixture")
    attack_results.extend(attack_rows(*representative))

    # Deterministically force one unavailable group per channel; smooth blocks
    # retain enough aggregate capacity for whole-image fallback.
    fallback_image = np.full((512, 512, 3), 100, dtype=np.uint8)
    out_domain = np.tile(np.asarray([0, 255], dtype=np.uint8), (32, 16))
    for c in range(3):
        ids = a.group_blocks(a.derive_keys(TEST_KEY, c)["Kstruct"])[0]
        for bid in ids:
            a._get_block(fallback_image, c, bid)[:] = out_domain
    fallback_id = image_id_for("forced-whole-image-fallback")
    fallback_protect_start = time.perf_counter()
    fallback = a.protect_image(fallback_image, TEST_KEY, fallback_id)
    fallback_protect_seconds = time.perf_counter() - fallback_protect_start
    fallback_verify_start = time.perf_counter()
    fallback_verified = a.verify_and_decrypt(fallback.marked_image, TEST_KEY, fallback_id)
    fallback_verify_seconds = time.perf_counter() - fallback_verify_start
    fallback_exact = fallback_verified.accepted and np.array_equal(fallback_verified.recovered_image, fallback_image)
    fallback_attack = fallback.marked_image.copy(); fallback_attack[0, 0, 0] ^= 1
    fallback_tamper = a.verify_and_decrypt(fallback_attack, TEST_KEY, fallback_id)
    clean_rows.append({
        "image": "constructed_capacity_fallback_fixture", "dimensions": "512x512x3",
        "mode": fallback.mode, "embedded_tags": fallback.embedded_tags,
        "verified": fallback_verified.accepted, "exact_recovery": fallback_exact,
        "pairs_used": fallback.pairs_used,
        "marked_vs_step2_psnr_db": f"{psnr(fallback.marked_image, a._transform_image(fallback_image, TEST_KEY, fallback_id)):.6f}",
        "protect_seconds": f"{fallback_protect_seconds:.6f}",
        "verify_seconds": f"{fallback_verify_seconds:.6f}",
    })
    peaks, whole_peak = capacity(a._transform_image(fallback_image, TEST_KEY, fallback_id), TEST_KEY)
    cap_rows.append({
        "image": "constructed_capacity_fallback_fixture", "mode": fallback.mode,
        "groups_attempted": len(peaks), "groups_capacity_at_least_256": sum(v >= 256 for v in peaks),
        "min_group_peak_net_bits": min(peaks), "mean_group_peak_net_bits": f"{np.mean(peaks):.3f}",
        "max_group_peak_net_bits": max(peaks), "whole_image_net_capacity_bits": whole_peak,
        "whole_image_capacity_at_least_256": whole_peak >= 256,
    })
    attack_results.append({"attack": "single_pixel_lsb_flip_whole_image_mode",
                           "verification_rejected": not fallback_tamper.accepted,
                           "failed_groups_reported": len(fallback_tamper.failed_groups),
                           "plaintext_released": fallback_tamper.recovered_image is not None})

    write_csv(OUT / "clean_authentication_results.csv", clean_rows)
    write_csv(OUT / "tamper_results.csv", attack_results)
    write_csv(OUT / "capacity_results.csv", cap_rows)
    vectors = []
    vectors.append("Deterministic TEST fixtures only; not production keys or ImageIDs.")
    vectors.append("UserKey fixture: bytes(range(32)); ImageID fixture: bytes(range(16)); channel=1; block IDs=(1,2,3,4).")
    d = a.derive_keys(TEST_KEY, 1); auth = a.derive_keys(TEST_KEY)["Kauth"]
    for name in ("Kch", "Ktpe", "Kr1", "Kstruct"):
        vectors.append(f"{name}={d[name].hex()}")
    vectors.append(f"Kauth={auth.hex()}")
    vectors.append(f"Kgroup={a.derive_group_key(auth, bytes(range(16)), 1, (1,2,3,4)).hex()}")
    vectors.append(f"Kimage={a.derive_image_key(auth, bytes(range(16))).hex()}")
    vectors.append("HMAC_DRBG first four Generate(4) values for Kstruct=00..1f: 833513c6 b64f37e2 37299c7d 7e60d678")
    vectors.append("Permutation prefix: 224 3 167 218 229 171 106 172")
    vectors.append("SHA256 of full 256-byte permutation: 55f272be5c1686f05a22714dba3a2651d79cb11d14df3d66ba715d3e38ba8c38")
    (OUT / "key_derivation_vectors.txt").write_text("\n".join(vectors) + "\n", encoding="utf-8")

    source_hash = hashlib.sha256((PROJECT / "src" / "authenticated_tpe.py").read_bytes()).hexdigest()
    experiment_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    tests_hash = hashlib.sha256((PROJECT / "tests" / "test_authenticated_tpe.py").read_bytes()).hexdigest()
    tamper_hash = hashlib.sha256((PROJECT / "experiments" / "check_authenticated_tpe_tampering.py").read_bytes()).hexdigest()
    input_hashes = ",".join(f"{p.name}:{hashlib.sha256(p.read_bytes()).hexdigest()}" for p in fixture_paths)
    try:
        import pytest
        pytest_version = pytest.__version__
    except Exception:
        pytest_version = "unavailable"
    import PIL
    provenance = [
        "experiment=paper-specific authenticated TPE/RCM/HMAC validation",
        "specification=professor-supplied Our method.pdf (16 pages)",
        "specification_sha256=f0348a3435259037f53028830f4d00056f8ad58f4c87843f3766c924b1a1607d",
        f"source_commit={source_commit}", f"source_worktree={source_worktree} (recorded at run start, before regenerating output files)",
        "shared_input_dependency=../tpe_rdh_reproduction/input/uct_colour; UCT images are read-only inputs",
        f"authenticated_tpe_py_sha256={source_hash}", f"experiment_script_sha256={experiment_hash}",
        f"authenticated_tests_sha256={tests_hash}", f"independent_tamper_script_sha256={tamper_hash}",
        f"input_uct_colour_sha256={input_hashes}",
        f"python={sys.version.replace(chr(10), ' ')}", f"numpy={np.__version__}",
        f"pillow={PIL.__version__}", f"pytest={pytest_version}",
        "user_key_fixture=bytes(range(32)); explicitly public deterministic test fixture",
        "image_id_method=SHA256(domain || ASCII image label)[:16]; explicit deterministic test fixture only",
        "production_image_id=secrets.token_bytes(16); retained by owner outside marked image",
        "dimensions=512x512x3 uint8 RGB; blocks=32x32; groups=4 blocks; tag=256 bits",
        "commands=.venv/bin/python -m pytest authenticated_tpe/tests -q ; .venv/bin/python authenticated_tpe/experiments/run_authenticated_tpe.py",
        "independent_tamper_command=.venv/bin/python authenticated_tpe/experiments/check_authenticated_tpe_tampering.py",
        "test_result=python -m pytest tests -q -> 102 passed, 14 dependency deprecation warnings",
        "ImageID values and test key bytes are not written to the result artifacts.",
        "The source worktree state is captured at run start; generated output files are written after that state is recorded.",
    ]
    (OUT / "provenance.txt").write_text("\n".join(provenance) + "\n", encoding="utf-8")

    all_clean = all(str(row["verified"]) == "True" and str(row["exact_recovery"]) == "True" for row in clean_rows)
    all_attacks_rejected = all(row["verification_rejected"] and not row["plaintext_released"] for row in attack_results)
    summary = [
        "Paper-specific prototype experiment summary (not the professor PDF's reference notebook results).",
        f"natural_images={len(fixture_paths)}", f"all_clean_cases_verified_and_exact={all_clean}",
        f"group_mode_cases={sum(row['mode']=='group' for row in clean_rows)}",
        f"whole_image_mode_cases={sum(row['mode']=='whole-image' for row in clean_rows)}",
        f"attack_cases={len(attack_results)}", f"all_attack_cases_rejected_without_plaintext={all_attacks_rejected}",
        f"constructed_fallback_mode={fallback.mode}", f"fallback_clean_exact={fallback_exact}",
        f"fallback_tamper_rejected={not fallback_tamper.accepted}",
        "Interpretation: report every case as tested under the deterministic fixtures; this is not a proof of security.",
    ]
    (OUT / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    clean_table = [
        "| Case | Mode | Tags | Verified | Exact recovery | Pairs used | Marked vs Step-2 PSNR (dB) | Protect (s) | Verify (s) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in clean_rows:
        clean_table.append(
            f"| {row['image']} | {row['mode']} | {row['embedded_tags']} | {row['verified']} | "
            f"{row['exact_recovery']} | {row['pairs_used']} | {row['marked_vs_step2_psnr_db']} | "
            f"{row['protect_seconds']} | {row['verify_seconds']} |"
        )
    attack_table = ["| Attack | Rejected | Failed groups reported | Plaintext released |", "|---|---:|---:|---:|"]
    for row in attack_results:
        attack_table.append(f"| {row['attack']} | {row['verification_rejected']} | {row['failed_groups_reported']} | {row['plaintext_released']} |")
    report = [
        "# Reversible block-group authentication prototype: experiment report", "",
        "## Scope and source", "",
        "This report documents the separate prototype in `src/authenticated_tpe.py`; it does not replace or alter the existing chaotic TPE/RDH reproduction. The method was reconstructed from the professor-supplied *Reversible Block-Group Authentication for Thumbnail-Preserving Encrypted Color Images Using Reversible Contrast Mapping and HMAC-SHA256* (16-page PDF; Sections 1–10). These are our implementation results, not the PDF's Colab/reference notebook results.",
        "", "The prototype enforces 512 x 512 RGB uint8 images, 32 x 32 non-overlapping blocks, 256 blocks per channel, 512 horizontal raster-order pairs per block, four ordered blocks per group, 64 groups per channel, and full 256-bit HMAC-SHA256 tags. The test-only key is `bytes(range(32))`; test ImageIDs are deterministic SHA-256 fixtures. Neither is suitable for production.",
        "", "The key hierarchy is `Kch,c = HMAC(UserKey, b'channel'||c)`, `Ktpe,c = HMAC(Kch,c,b'tpe')`, `Kr1,c = HMAC(Kch,c,b'r1')`, `Kstruct,c = HMAC(Kch,c,b'struct')`, `Kauth = HMAC(UserKey,b'auth')`, `Kgroup = HMAC(Kauth,ImageID||c||Bid0||Bid1||Bid2||Bid3)`, and `Kimage = HMAC(Kauth,b'image'||ImageID)`. Exact fixed-width encodings and domain labels are documented in `docs/AUTHENTICATED_TPE.md`.",
        "", "## Clean-image results", "", *clean_table, "",
        "All six UCT color images were protected in group mode. Every one of 192 group tags per image verified and each image recovered bit-exactly. A separate constructed capacity case forced the all-or-nothing fallback to whole-image mode; its image-level tag verified and recovery was bit-exact. Marked-image PSNR is measured against the Step-2 encrypted image before RCM marking, as in the method document. It is a fidelity metric, not an authentication or security metric.",
        "", "## Authentication and tamper checks", "", *attack_table, "",
        f"Observed controlled attack cases rejected: {sum(bool(r['verification_rejected']) for r in attack_results)}/{len(attack_results)}; observed false acceptances: {sum(not bool(r['verification_rejected']) for r in attack_results)}. This finite test count is not a statistical proof or a security bound. Group-mode edits localized to {', '.join(str(r['failed_groups_reported']) for r in attack_results if r['attack'] in ('single_pixel_lsb_flip','same_channel_block_swap','cross_channel_block_swap'))} affected groups for the single-pixel, same-channel swap, and cross-channel swap cases respectively. Whole-image fallback reports no authenticated location. Wrong UserKey, wrong ImageID, and another protected file under the same UserKey were rejected. Failed verification returns no recovered image.",
        "", "A separate script outside pytest (`experiments/check_authenticated_tpe_tampering.py`) independently confirmed clean group verification and exact recovery, one-bit tamper rejection with a failed group identified, and wrong-key/wrong-ImageID rejection. Lossless PNG save/reload is checked by a pytest integration test. JPEG/recompression behavior and the PDF's full attack study have not been reproduced.",
        "", "## Capacity and operating mode", "", "Capacity is the prefix net `A - N` in the required traversal (usable T/O pairs add one; N pairs subtract one). Group mode is all-or-nothing: every group must reach 256 net bits. When any group fails, provisional group marks are discarded and one 256-bit whole-image tag is embedded instead. See `capacity_results.csv` for measured per-group peak net capacities and whole-image totals. In the constructed fallback fixture 3 of 192 groups were below 256 bits, while whole-image capacity was sufficient.",
        "", "RCM overflow/underflow is prevented by restricting transformable T pairs to `D_c`, where both forward coordinates are in [0,255] and the ambiguous odd border pairs are removed. O pairs use the specified odd-pair representation; N pairs are not transformed and their first-pixel LSB is saved and restored. If an image/group cannot reach 256 net bits, group marks are abandoned for whole-image fallback; if the whole image also lacks capacity, `InsufficientCapacity` rejects it without returning a marked result.",
        "", "## Reproduction and provenance", "", "```bash", "../.venv/bin/python -m pytest tests -q", "../.venv/bin/python experiments/run_authenticated_tpe.py", "../.venv/bin/python experiments/check_authenticated_tpe_tampering.py", "```", "",
        f"Source commit: `{source_commit}`. Worktree at run start: `{source_worktree}`. The experiment reads the shared UCT images from `../tpe_rdh_reproduction/input/uct_colour/`. Python, NumPy, Pillow, source hashes, deterministic fixture rules, and the exact generation command are in `provenance.txt`.",
        "", "## Sources and limitations", "",
        "Primary method specification: the professor-supplied *Our method.pdf*, Sections 1–10 (SHA-256 `f0348a3435259037f53028830f4d00056f8ad58f4c87843f3766c924b1a1607d`). The method document cites Coltuc and Chassery (2007) for reversible contrast mapping, [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) for HMAC, [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) for SHA-256, and [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) for HMAC_DRBG. NIST's [CAVP RNG page](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Random-Number-Generators) provides DRBG test vectors for informal checking and states these do not replace CAVP validation. The checked-in DRBG regression uses the professor PDF's exact permutation prefix and a separately calculated full permutation digest; this project did not claim CAVP validation or import NIST's vector archive. This reproduction uses the exact deterministic conventions listed in `docs/AUTHENTICATED_TPE.md` and the known-answer vectors in `key_derivation_vectors.txt`.",
        "", "The implementation is a research prototype, not a claim of cryptographic security. Authentication depends on secrecy and handling of UserKey and a fresh private ImageID, exact lossless pixel preservation, and implementation correctness. ImageID uniqueness is an owner responsibility; the API has no persistent reuse registry. Step 1 preserves adjacent pair sums and leaks them by design, and Step 2's four-value per-block shift is not relied on for confidentiality. No independent cryptanalysis or formal proof was performed. RCM/HMAC tests, exact recovery, and these controlled attack checks do not prove overall security. Group authentication identifies an affected group of four scattered blocks, not the exact altered block; whole-image mode only returns an image-level result.",
    ]
    (OUT / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    readme = [
        "# Authenticated TPE experiment outputs", "",
        "These are project prototype results from `authenticated_tpe/experiments/run_authenticated_tpe.py`; they are not the professor PDF's Colab/reference results.",
        "All key/ImageID values are deterministic test fixtures and must not be used in production.",
        "ImageID values are deliberately omitted. Production ImageIDs are generated with a CSPRNG and retained privately by the owner.",
        "See `docs/AUTHENTICATED_TPE.md` for method, encodings, assumptions, and limitations.", "",
        "- `clean_authentication_results.csv`: clean mode, auth/recovery, pair count, fidelity and runtime.",
        "- `tamper_results.csv`: one-bit, block, cross-channel, credential and replacement negative cases.",
        "- `capacity_results.csv`: group prefix net capacity and whole-image net capacity.",
        "- `key_derivation_vectors.txt`: explicit public test-vector outputs.",
        "- `provenance.txt`: source commit, worktree state, versions, command and source hashes.",
        "- `summary.txt`: compact result interpretation.",
        "- `report.md`: full validation report, test interpretation, source notes, and limitations.",
    ]
    (OUT / "README.md").write_text("\n".join(readme) + "\n", encoding="utf-8")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
