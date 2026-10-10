#!/usr/bin/env python3
"""Image-level, authentication and differential metrics for the revised build.

Produces:

*   ``image_quality.csv``          - recovery, fidelity, entropy, correlation, timing
*   ``npcr_uaci.csv``              - correct NPCR/UACI between two ciphertexts of one
                                     plaintext, plus the old report's plaintext-vs-marked
                                     quantity for comparison
*   ``tamper_results.csv``         - controlled tamper / wrong-key / wrong-ID rejection
*   ``same_key_cases.csv``         - same-key, different-image / different-ImageID effects
*   ``class_uniformity.csv``       - per distinct sum-class size, Holm-corrected
*   ``reduction_detail.csv``       - direct chi-square on the final reduced offset
*   ``metrics_summary.json``       - machine-readable roll-up

Two methodological points that are deliberately *not* smoothed over:

1.  A thumbnail-preserving ciphertext keeps every adjacent pair sum, so two
    ciphertexts of the same plaintext differ only by a rotation inside each sum
    class.  NPCR/UACI therefore cannot reach their diffusion ideals for this
    scheme; the measured values are reported with that explanation.
2.  Substituting a different *valid* ciphertext produced under the same UserKey
    and the same ImageID is accepted, because the tag authenticates the
    ciphertext content.  It is reported as an accepted substitution, not as a
    rejected forgery.
"""
from __future__ import annotations

import concurrent.futures
import csv
import hashlib
import json
import sys
import time
from pathlib import Path

import numpy as np
from PIL import Image
from skimage.metrics import peak_signal_noise_ratio, structural_similarity

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
REPO = ROOT.parent

import atpe_v2 as v2  # noqa: E402
import streams as S  # noqa: E402

OUT = ROOT / "output" / "metrics"
KEY = bytes(range(32))
IMAGE_ID = bytes(range(16))
UID_IMAGES = list(S.UCT_NAMES)


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def entropy(array: np.ndarray) -> float:
    counts = np.bincount(np.asarray(array, dtype=np.uint8).ravel(),
                         minlength=256).astype(np.float64)
    probabilities = counts / counts.sum()
    probabilities = probabilities[probabilities > 0]
    return float(-(probabilities * np.log2(probabilities)).sum())


def correlation(array: np.ndarray, axis: int) -> float:
    a = np.asarray(array, dtype=np.float64)
    first = a[:, :-1] if axis == 0 else a[:-1, :]
    second = a[:, 1:] if axis == 0 else a[1:, :]
    return float(np.corrcoef(first.ravel(), second.ravel())[0, 1])


def image_at(index: int) -> np.ndarray:
    return S.load_image(index)


def quality_case(index: int) -> dict:
    image = image_at(index)
    label = UID_IMAGES[index] if index < len(UID_IMAGES) else f"ucid_{index + 1}"
    image_id = S.pool_image_id(5000 + index)
    key = S.pool_key(5000 + index)
    start = time.perf_counter()
    protected = v2.protect_image(image, key, image_id)
    protect_seconds = time.perf_counter() - start
    start = time.perf_counter()
    verified = v2.verify_and_decrypt(protected.marked_image, key, image_id)
    verify_seconds = time.perf_counter() - start
    step2 = v2.base._step2_image(v2.step1_image(image, key, image_id), key)
    marked = protected.marked_image
    recovered = verified.recovered_image
    return {
        "image": label,
        "image_order": index,
        "image_sha256": hashlib.sha256(image.tobytes(order="C")).hexdigest(),
        "mode": protected.mode,
        "pairs_used": protected.pairs_used,
        "authentication_accepted": verified.accepted,
        "exact_recovery": bool(np.array_equal(recovered, image)),
        "max_abs_error": int(np.abs(recovered.astype(int) - image.astype(int)).max()),
        "recovery_mse": float(np.mean((recovered.astype(float) - image.astype(float)) ** 2)),
        "recovery_psnr_db": float(peak_signal_noise_ratio(image, recovered, data_range=255)),
        "recovery_ssim": float(structural_similarity(image, recovered, channel_axis=2,
                                                     data_range=255)),
        "marked_vs_step2_psnr_db": float(peak_signal_noise_ratio(step2, marked, data_range=255)),
        "marked_vs_step2_ssim": float(structural_similarity(step2, marked, channel_axis=2,
                                                            data_range=255)),
        "plaintext_vs_marked_psnr_db": float(peak_signal_noise_ratio(image, marked,
                                                                     data_range=255)),
        "plaintext_vs_marked_ssim": float(structural_similarity(image, marked, channel_axis=2,
                                                                data_range=255)),
        # The quantities the earlier report published under the names NPCR/UACI:
        # differences between a marked image and its own Step-2 intermediate.
        "marked_vs_step2_npcr_percent": float(
            (marked.astype(np.int32) != step2.astype(np.int32)).mean() * 100.0),
        "marked_vs_step2_uaci_percent": float(
            (np.abs(marked.astype(np.int32) - step2.astype(np.int32)) / 255.0).mean() * 100.0),
        "plaintext_vs_marked_npcr_percent": float(
            (image.astype(np.int32) != marked.astype(np.int32)).mean() * 100.0),
        "plaintext_vs_marked_uaci_percent": float(
            (np.abs(image.astype(np.int32) - marked.astype(np.int32)) / 255.0).mean() * 100.0),
        "entropy_plaintext": entropy(image),
        "entropy_marked": entropy(marked),
        "entropy_step1": entropy(v2.step1_image(image, key, image_id)),
        "corr_plaintext_h": correlation(image, 0),
        "corr_plaintext_v": correlation(image, 1),
        "corr_marked_h": correlation(marked, 0),
        "corr_marked_v": correlation(marked, 1),
        "protect_seconds": protect_seconds,
        "verify_seconds": verify_seconds,
        "ciphertext_sha256": hashlib.sha256(marked.tobytes(order="C")).hexdigest(),
    }


def _npcr_uaci(a: np.ndarray, b: np.ndarray) -> tuple[float, float]:
    first = a.astype(np.int32)
    second = b.astype(np.int32)
    npcr = float((first != second).astype(np.float64).mean() * 100.0)
    uaci = float((np.abs(first - second) / 255.0).mean() * 100.0)
    return npcr, uaci


def differential_case(index: int) -> dict:
    """Two ciphertexts of ONE plaintext under two different (UserKey, ImageID) pairs."""
    image = image_at(index)
    label = UID_IMAGES[index] if index < len(UID_IMAGES) else f"ucid_{index + 1}"
    c1 = v2.protect_image(image, S.pool_key(6001 + index), S.pool_image_id(6401 + index)).marked_image
    c2 = v2.protect_image(image, S.pool_key(6301 + index), S.pool_image_id(6402 + index)).marked_image
    npcr, uaci = _npcr_uaci(c1, c2)
    legacy_npcr, legacy_uaci = _npcr_uaci(image, c1)
    return {"image": label, "image_order": index,
            "npcr_percent": npcr, "uaci_percent": uaci,
            "plaintext_vs_marked_npcr_percent": legacy_npcr,
            "plaintext_vs_marked_uaci_percent": legacy_uaci,
            "cipher1_sha256": hashlib.sha256(c1.tobytes(order="C")).hexdigest(),
            "cipher2_sha256": hashlib.sha256(c2.tobytes(order="C")).hexdigest()}


def tamper_cases() -> list[dict]:
    image = image_at(0)
    protected = v2.protect_image(image, KEY, IMAGE_ID)
    marked = protected.marked_image
    cases: list[tuple[str, str, np.ndarray, bytes, bytes]] = []
    one_bit = marked.copy()
    one_bit[0, 0, 0] ^= 1
    cases.append(("single_pixel_lsb_flip", "forgery", one_bit, KEY, IMAGE_ID))
    block_a = v2.base._get_block(marked, 0, 0).copy()
    block_b = v2.base._get_block(marked, 0, 1).copy()
    swap = marked.copy()
    v2.base._get_block(swap, 0, 0)[:] = block_b
    v2.base._get_block(swap, 0, 1)[:] = block_a
    cases.append(("same_channel_block_swap", "forgery", swap, KEY, IMAGE_ID))
    cross = marked.copy()
    other = v2.base._get_block(marked, 1, 0).copy()
    v2.base._get_block(cross, 0, 0)[:] = other
    v2.base._get_block(cross, 1, 0)[:] = block_a
    cases.append(("cross_channel_block_swap", "forgery", cross, KEY, IMAGE_ID))
    cases.append(("wrong_user_key", "wrong credential", marked,
                  bytes([KEY[0] ^ 1]) + KEY[1:], IMAGE_ID))
    cases.append(("wrong_image_id", "wrong credential", marked, KEY,
                  bytes([IMAGE_ID[0] ^ 1]) + IMAGE_ID[1:]))
    replaced = v2.protect_image(image_at(1), KEY, IMAGE_ID).marked_image
    cases.append(("valid_ciphertext_of_another_image_same_key_and_id",
                  "valid substitution", replaced, KEY, IMAGE_ID))
    rows = []
    for name, kind, attacked, key, image_id in cases:
        result = v2.verify_and_decrypt(attacked, key, image_id)
        rows.append({
            "case": name,
            "case_kind": kind,
            "rejected": not result.accepted,
            "mode_reported": result.mode or "none",
            "failed_groups_reported": len(result.failed_groups),
            "plaintext_released": result.recovered_image is not None,
            "reason": result.reason,
        })
    clean = v2.verify_and_decrypt(marked, KEY, IMAGE_ID)
    rows.append({"case": "positive_control_clean", "case_kind": "positive control",
                 "rejected": not clean.accepted, "mode_reported": clean.mode or "none",
                 "failed_groups_reported": len(clean.failed_groups),
                 "plaintext_released": clean.recovered_image is not None,
                 "reason": clean.reason})
    return rows


def same_key_cases() -> list[dict]:
    image_a, image_b = image_at(0), image_at(1)
    key = S.pool_key(7001)
    id_a, id_b = S.pool_image_id(7001), S.pool_image_id(7002)
    ktpe = v2.derive_keys(key, 0)["Ktpe"]
    rows = []
    for label, first, second, first_id, second_id in [
            ("different ImageID, different image", image_a, image_b, id_a, id_b),
            ("different ImageID, same image", image_a, image_a, id_a, id_b),
            ("same ImageID, different image", image_a, image_b, id_a, id_a),
            ("same ImageID, same image", image_a, image_a, id_a, id_a)]:
        step1_a = v2.step1_image(first, key, first_id)
        step1_b = v2.step1_image(second, key, second_id)
        cipher_a = v2.protect_image(first, key, first_id).marked_image
        cipher_b = v2.protect_image(second, key, second_id).marked_image
        shift_a = v2.pair_shift(ktpe, first_id, 0, 0, 128)
        shift_b = v2.pair_shift(ktpe, second_id, 0, 0, 128)
        tag_a = v2.group_tag_bytes_from_image(first, key, first_id)[:32]
        tag_b = v2.group_tag_bytes_from_image(second, key, second_id)[:32]
        rows.append({
            "case": label,
            "image_id_a_sha256": hashlib.sha256(first_id).hexdigest(),
            "image_id_b_sha256": hashlib.sha256(second_id).hexdigest(),
            "step1_identical": bool(np.array_equal(step1_a, step1_b)),
            "keystream_offset_a": shift_a,
            "keystream_offset_b": shift_b,
            "keystream_identical": shift_a == shift_b,
            "first_tag_identical": tag_a == tag_b,
            "ciphertext_identical": bool(np.array_equal(cipher_a, cipher_b)),
            "ciphertext_sha256_a": hashlib.sha256(cipher_a.tobytes(order="C")).hexdigest(),
            "ciphertext_sha256_b": hashlib.sha256(cipher_b.tobytes(order="C")).hexdigest(),
        })
    return rows


def _uniform_words(count: int) -> np.ndarray:
    """Distinct 32-bit Step-1 PRF words drawn from several disjoint instances."""
    import hashlib as _hashlib
    import hmac as _hmac

    words = np.empty(count, dtype=np.uint64)
    filled = 0
    instance = 0
    while filled < count:
        key = S.pool_key(9000 + instance)
        image_id = S.pool_image_id(9000 + instance)
        ktpe = v2.derive_keys(key, 0)["Ktpe"]
        stop = False
        for block in range(256):
            for pair in range(512):
                if filled >= count:
                    stop = True
                    break
                digest = _hmac.new(ktpe, v2.pair_shift_message(image_id, block, pair),
                                   _hashlib.sha256).digest()
                words[filled] = int.from_bytes(digest[:4], "big")
                filled += 1
            if stop:
                break
        instance += 1
    return words


def _holm(p_values: list[float], alpha: float = 0.01) -> list[bool]:
    order = sorted(range(len(p_values)), key=lambda i: p_values[i])
    rejected = [False] * len(p_values)
    total = len(p_values)
    for rank, index in enumerate(order):
        if p_values[index] <= alpha / (total - rank):
            rejected[index] = True
        else:
            break
    return rejected


def class_uniformity(samples: int = 200_000) -> list[dict]:
    """Uniformity of the raw ``w mod s`` reduction, one row per distinct class size.

    The hypothesis for a class size is shared by every class of that size, so the
    family is the set of distinct sizes and Holm-Bonferroni keeps the family-wise
    error rate at 0.01.
    """
    from scipy.stats import chisquare

    words = _uniform_words(samples)
    sizes = sorted({len(values) for values in v2.base._SUM_CLASSES.values()})
    rows, p_values = [], []
    for size in sizes:
        if size < 2:
            continue
        counts = np.bincount(words % size, minlength=size)
        statistic, p_value = chisquare(counts)
        p_values.append(float(p_value))
        rows.append({"class_size": size, "samples": samples,
                     "chi_square": float(statistic), "p_value": float(p_value)})
    rejected = _holm(p_values, 0.01)
    for row, reject in zip(rows, rejected):
        row["uncorrected_p_below_0.01"] = row["p_value"] < 0.01
        row["holm_rejected_at_0.01"] = bool(reject)
        row["distinct_sizes_tested"] = len(rows)
        row["expected_false_positives_at_0.01"] = round(0.01 * len(rows), 2)
    return rows


def reduction_detail(draws: int = 200_000,
                     sizes: tuple[int, ...] = (2, 3, 4, 7, 23, 74, 128, 255, 256)) -> list[dict]:
    """Chi-square on the final ``pair_shift`` offset (rejection sampling included)."""
    from scipy.stats import chisquare

    rows = []
    instance = 0
    for size in sizes:
        counts = np.zeros(size, dtype=np.int64)
        filled = 0
        while filled < draws:
            key = S.pool_key(9500 + instance)
            image_id = S.pool_image_id(9500 + instance)
            ktpe = v2.derive_keys(key, 0)["Ktpe"]
            stop = False
            for block in range(256):
                for pair in range(512):
                    if filled >= draws:
                        stop = True
                        break
                    counts[v2.pair_shift(ktpe, image_id, block, pair, size)] += 1
                    filled += 1
                if stop:
                    break
            instance += 1
        statistic, p_value = chisquare(counts)
        rows.append({"class_size": size, "draws": draws,
                     "chi_square": float(statistic), "p_value": float(p_value),
                     "uniform_at_0.01": bool(p_value >= 0.01),
                     "rejection_branch_active": bool((1 << 32) % size != 0)})
    return rows


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ProcessPoolExecutor(max_workers=6) as executor:
        quality = list(executor.map(quality_case, range(0, 6)))
        differential = list(executor.map(differential_case, range(6, 26)))
    write_csv(OUT / "image_quality.csv", quality)
    write_csv(OUT / "npcr_uaci.csv", differential)
    tamper = tamper_cases()
    write_csv(OUT / "tamper_results.csv", tamper)
    same_key = same_key_cases()
    write_csv(OUT / "same_key_cases.csv", same_key)
    uniformity = class_uniformity()
    write_csv(OUT / "class_uniformity.csv", uniformity)
    detail = reduction_detail()
    write_csv(OUT / "reduction_detail.csv", detail)

    forgeries = [row for row in tamper if row["case_kind"] in ("forgery", "wrong credential")]
    substitution = next(row for row in tamper
                        if row["case_kind"] == "valid substitution")
    control = next(row for row in tamper if row["case_kind"] == "positive control")
    summary = {
        "revision": v2.activation_status(),
        "uct_images_evaluated": len(quality),
        "exact_recovery_all": all(row["exact_recovery"] for row in quality),
        "authentication_all_accepted": all(row["authentication_accepted"] for row in quality),
        "modes": {row["image"]: row["mode"] for row in quality},
        "npcr_mean_percent": float(np.mean([row["npcr_percent"] for row in differential])),
        "uaci_mean_percent": float(np.mean([row["uaci_percent"] for row in differential])),
        "npcr_ideal_percent": 99.6094,
        "uaci_ideal_percent": 33.4635,
        "diffusion_note": "NPCR/UACI cannot reach their ideal values here: a "
                          "thumbnail-preserving ciphertext preserves every adjacent pair sum, "
                          "so the two ciphertexts of one plaintext differ only by rotations "
                          "inside the sum classes.",
        "legacy_plaintext_vs_marked_npcr_mean_percent": float(np.mean(
            [row["plaintext_vs_marked_npcr_percent"] for row in differential])),
        "legacy_plaintext_vs_marked_uaci_mean_percent": float(np.mean(
            [row["plaintext_vs_marked_uaci_percent"] for row in differential])),
        "forgery_cases": len(forgeries),
        "forgery_rejected_all": all(row["rejected"] for row in forgeries),
        "forgery_plaintext_leaked": any(row["plaintext_released"] for row in forgeries),
        "valid_substitution_accepted": not substitution["rejected"],
        "valid_substitution_note": "a valid ciphertext of another image, produced under the same "
                                   "UserKey and ImageID, verifies: the tag authenticates ciphertext "
                                   "content and the scheme does not bind image identity, which is "
                                   "why a fresh ImageID per image is required",
        "clean_control_accepted": not control["rejected"],
        "same_key_cases": same_key,
        "class_uniformity_sizes": len(uniformity),
        "class_uniformity_uncorrected_failures": sum(
            row["uncorrected_p_below_0.01"] for row in uniformity),
        "class_uniformity_expectation": round(0.01 * len(uniformity), 2),
        "class_uniformity_holm_rejections": sum(row["holm_rejected_at_0.01"] for row in uniformity),
        "reduction_detail_all_uniform": all(row["uniform_at_0.01"] for row in detail),
    }
    (OUT / "metrics_summary.json").write_text(json.dumps(summary, indent=2) + "\n",
                                              encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "same_key_cases"}, indent=2))


if __name__ == "__main__":
    main()