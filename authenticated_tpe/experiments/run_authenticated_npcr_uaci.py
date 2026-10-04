"""Run authenticated-TPE differential, key-sensitivity, and consistency checks."""
from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import sys
from pathlib import Path

import numpy as np
from PIL import Image

PROJECT = Path(__file__).resolve().parents[1]
REPO = PROJECT.parent
sys.path.insert(0, str(PROJECT / "src"))
import authenticated_tpe as auth
from statistical_eval import deterministic_test_image_id, flip_first_key_bit, make_differential_plaintext, npcr_uaci

INPUT_DIR = REPO / "tpe_rdh_reproduction/input/uct_colour"
OUT = PROJECT / "output"
IMAGE_NAMES = ("airplane", "baboon", "couple", "girl", "lena", "peppers")
BLOCK_SIZE = 32
TEST_KEY = bytes(range(32))  # Public test fixture only.
FIXED_ID = deterministic_test_image_id("authenticated-tpe-differential-fixed")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rgb_hash(image: np.ndarray) -> str:
    return sha(np.asarray(image, dtype=np.uint8).tobytes(order="C"))


def read_rgb(path: Path) -> tuple[np.ndarray, str]:
    source_hash = sha(path.read_bytes())
    with Image.open(path) as im:
        im = im.convert("RGB")
        if im.size != (512, 512):
            if im.size != (256, 256):
                raise ValueError(f"unexpected UCT dimensions: {path.name} {im.size}")
            im = im.resize((512, 512))  # Same Pillow default as the auth prototype runner.
        return np.asarray(im, dtype=np.uint8), source_hash


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError(f"no rows to write: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        fieldnames = list(dict.fromkeys(key for row in rows for key in row))
        writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def metric_rows(experiment: str, image: str, values: dict, metadata: dict) -> list[dict]:
    return [
        {"experiment": experiment, "image": image, "channel": channel,
         "npcr_percent": f"{values[channel][0]:.8f}", "uaci_percent": f"{values[channel][1]:.8f}",
         "changed_samples": values[channel][2], "sample_count": values[channel][3], **metadata}
        for channel in ("R", "G", "B", "RGB")
    ]


def stage_hashes(image: np.ndarray, iid: bytes) -> tuple[str, str]:
    step1 = auth._step1_image(image, TEST_KEY, iid)
    step2 = auth._step2_image(step1, TEST_KEY)
    return rgb_hash(step1), rgb_hash(step2)


def verify_exact(marked: np.ndarray, image: np.ndarray, key: bytes, iid: bytes) -> tuple[bool, str]:
    result = auth.verify_and_decrypt(marked, key, iid)
    exact = result.accepted and np.array_equal(result.recovered_image, image)
    return exact, "" if result.recovered_image is None else rgb_hash(result.recovered_image)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    flipped_key = flip_first_key_bit(TEST_KEY)
    plain_rows: list[dict] = []
    key_rows: list[dict] = []
    per_image_pairs: dict[str, tuple[np.ndarray, np.ndarray]] = {}
    key_image_pairs: dict[str, tuple[np.ndarray, np.ndarray]] = {}
    consistency: list[dict] = []
    loaded: dict[str, tuple[np.ndarray, str]] = {}

    for name in IMAGE_NAMES:
        image, file_hash = read_rgb(INPUT_DIR / f"{name}.tif")
        loaded[name] = image, file_hash
        modified = make_differential_plaintext(image, BLOCK_SIZE)
        if int(np.count_nonzero(modified != image)) != image.shape[0] // BLOCK_SIZE * (image.shape[1] // BLOCK_SIZE):
            raise AssertionError("differential perturbation did not change exactly one R sample per block")

        base = auth.protect_image(image, TEST_KEY, FIXED_ID)
        changed = auth.protect_image(modified, TEST_KEY, FIXED_ID)
        base_ok, recovered_hash = verify_exact(base.marked_image, image, TEST_KEY, FIXED_ID)
        changed_ok, modified_recovered_hash = verify_exact(changed.marked_image, modified, TEST_KEY, FIXED_ID)
        if not (base_ok and changed_ok):
            raise AssertionError(f"valid differential outputs failed exact authenticated recovery for {name}")
        per_image_pairs[name] = (base.marked_image, changed.marked_image)
        metadata = {
            "source_image_sha256": file_hash,
            "processed_image_sha256": rgb_hash(image),
            "modified_image_sha256": rgb_hash(modified),
            "image_id_sha256": sha(FIXED_ID),
            "user_key_sha256": sha(TEST_KEY),
            "block_size": BLOCK_SIZE,
            "plaintext_change": "top-left sample of every 32x32 block; R channel; +1 unless 255 then -1",
            "image_id_policy": "same fixed deterministic test ImageID for both plaintexts",
            "base_authenticates_and_recovers": base_ok,
            "modified_authenticates_and_recovers": changed_ok,
        }
        plain_rows.extend(metric_rows("plaintext_difference_fixed_image_id", name,
                                      npcr_uaci(base.marked_image, changed.marked_image), metadata))

        key_changed = auth.protect_image(image, flipped_key, FIXED_ID)
        key_image_pairs[name] = (base.marked_image, key_changed.marked_image)
        base_key_ok, _ = verify_exact(base.marked_image, image, TEST_KEY, FIXED_ID)
        flipped_key_ok, _ = verify_exact(key_changed.marked_image, image, flipped_key, FIXED_ID)
        if not (base_key_ok and flipped_key_ok):
            raise AssertionError(f"key-sensitivity output failed authenticated exact recovery for {name}")
        key_metadata = {
            "source_image_sha256": file_hash,
            "processed_image_sha256": rgb_hash(image),
            "image_id_sha256": sha(FIXED_ID),
            "base_user_key_sha256": sha(TEST_KEY),
            "flipped_user_key_sha256": sha(flipped_key),
            "key_bit_change": "byte 0 XOR 0x01 (one bit), matching original key-sensitivity experiment",
            "block_size": BLOCK_SIZE,
            "payload": "none",
            "image_id_policy": "same fixed deterministic test ImageID under both keys",
            "base_authenticates_and_recovers": base_key_ok,
            "flipped_key_authenticates_and_recovers": flipped_key_ok,
        }
        key_rows.extend(metric_rows("one_bit_key_sensitivity_fixed_image_id", name,
                                    npcr_uaci(base.marked_image, key_changed.marked_image), key_metadata))

        repeated = auth.protect_image(image, TEST_KEY, FIXED_ID)
        different_id = deterministic_test_image_id(f"consistency-different-id-{name}")
        changed_id_result = auth.protect_image(image, TEST_KEY, different_id)
        step1_hash, step2_hash = stage_hashes(image, FIXED_ID)
        repeated_step1_hash, repeated_step2_hash = stage_hashes(image, FIXED_ID)
        verified, recovered = verify_exact(base.marked_image, image, TEST_KEY, FIXED_ID)
        iid_not_embedded = FIXED_ID not in base.marked_image.tobytes(order="C")
        if not (np.array_equal(base.marked_image, repeated.marked_image)
                and step1_hash == repeated_step1_hash and step2_hash == repeated_step2_hash
                and not np.array_equal(base.marked_image, changed_id_result.marked_image)
                and iid_not_embedded and verified):
            raise AssertionError(f"determinism, ImageID separation, or recovery check failed for {name}")
        consistency.append({
            "case": "same_image_same_key_same_id", "image": name,
            "source_image_sha256": file_hash, "processed_image_sha256": rgb_hash(image),
            "image_id_sha256": sha(FIXED_ID), "different_image_id_sha256": sha(different_id),
            "step1_sha256": step1_hash, "step2_sha256": step2_hash,
            "final_marked_sha256": rgb_hash(base.marked_image), "repeated_final_sha256": rgb_hash(repeated.marked_image),
            "recovered_image_sha256": recovered, "identical_repeat": True,
            "different_image_id_changes_output": True, "image_id_bytes_absent_from_marked_pixels": iid_not_embedded,
            "clean_exact_recovery": verified,
        })

    for experiment, pairs, target in (
        ("plaintext_difference_fixed_image_id", per_image_pairs, plain_rows),
        ("one_bit_key_sensitivity_fixed_image_id", {}, key_rows),
    ):
        if experiment == "plaintext_difference_fixed_image_id":
            aggregate_pairs = [per_image_pairs[name] for name in IMAGE_NAMES]
        else:
            aggregate_pairs = [key_image_pairs[name] for name in IMAGE_NAMES]
        base_stack = np.concatenate([pair[0] for pair in aggregate_pairs], axis=0)
        other_stack = np.concatenate([pair[1] for pair in aggregate_pairs], axis=0)
        aggregate_meta = {
            "source_image_sha256": "six UCT fixtures; see per-image rows",
            "processed_image_sha256": "aggregate", "modified_image_sha256": "aggregate",
            "image_id_sha256": sha(FIXED_ID), "user_key_sha256": sha(TEST_KEY),
            "block_size": BLOCK_SIZE, "plaintext_change": "six-image pooled aggregate",
            "image_id_policy": "fixed deterministic test ImageID",
            "base_authenticates_and_recovers": True, "modified_authenticates_and_recovers": True,
        }
        if experiment.startswith("one_bit"):
            aggregate_meta.update({"base_user_key_sha256": sha(TEST_KEY), "flipped_user_key_sha256": sha(flipped_key),
                                   "key_bit_change": "byte 0 XOR 0x01", "payload": "none",
                                   "flipped_key_authenticates_and_recovers": True})
        target.extend(metric_rows(experiment, "aggregate_six_images", npcr_uaci(base_stack, other_stack), aggregate_meta))

    write_csv(OUT / "npcr_uaci_results.csv", plain_rows)
    write_csv(OUT / "key_sensitivity_npcr_uaci.csv", key_rows)

    reuse_rows = []
    airplane, airplane_file_hash = loaded["airplane"]
    baboon, baboon_file_hash = loaded["baboon"]
    for variant, ids in (
        ("fixed_image_id_isolates_image_dependence", {"airplane": FIXED_ID, "baboon": FIXED_ID}),
        ("image_specific_deterministic_ids_follow_private_id_model", {
            "airplane": deterministic_test_image_id("same-key-different-image-airplane"),
            "baboon": deterministic_test_image_id("same-key-different-image-baboon"),
        }),
    ):
        outputs = {}
        stages = {}
        for name, image, file_hash in (("airplane", airplane, airplane_file_hash), ("baboon", baboon, baboon_file_hash)):
            iid = ids[name]
            stages[name] = stage_hashes(image, iid)
            protected = auth.protect_image(image, TEST_KEY, iid)
            exact, recovered_hash = verify_exact(protected.marked_image, image, TEST_KEY, iid)
            outputs[name] = (rgb_hash(image), file_hash, sha(iid), stages[name][0], stages[name][1],
                             rgb_hash(protected.marked_image), recovered_hash, exact)
        for name in ("airplane", "baboon"):
            img_hash, file_hash, iid_hash, s1_hash, s2_hash, final_hash, recovered_hash, exact = outputs[name]
            other = outputs["baboon" if name == "airplane" else "airplane"]
            reuse_rows.append({
                "variant": variant, "image": name, "same_user_key": True,
                "source_image_file_sha256": file_hash, "processed_image_sha256": img_hash,
                "image_id_sha256": iid_hash, "step1_sha256": s1_hash, "step2_sha256": s2_hash,
                "final_marked_sha256": final_hash, "recovered_image_sha256": recovered_hash,
                "image_differs_from_other": img_hash != other[0],
                "image_id_differs_from_other": iid_hash != other[2],
                "step1_differs_from_other": s1_hash != other[3], "step2_differs_from_other": s2_hash != other[4],
                "final_differs_from_other": final_hash != other[5], "exact_recovery": exact,
            })
            if not exact:
                raise AssertionError(f"same-key/different-image recovery failed for {name} in {variant}")
        if variant == "fixed_image_id_isolates_image_dependence":
            if not all(outputs[x][3] != outputs[y][3] and outputs[x][4] != outputs[y][4] and outputs[x][5] != outputs[y][5]
                       for x, y in [("airplane", "baboon")]):
                raise AssertionError("fixed-ID different-image case did not diversify intermediate and final data")
    write_csv(OUT / "same_key_different_image.csv", reuse_rows)
    write_csv(OUT / "consistency_hashes.csv", consistency)

    # Hash-only provenance: fixture secrets and private ImageID values are never serialized.
    try:
        git_commit = __import__("subprocess").check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip()
        git_state = "clean" if not __import__("subprocess").check_output(["git", "-C", str(REPO), "status", "--porcelain"], text=True).strip() else "dirty"
    except Exception:
        git_commit, git_state = "unknown", "unknown"
    input_hashes = [f"{n}.tif:{loaded[n][1]}" for n in IMAGE_NAMES]
    versions = {name: importlib.metadata.version(dist) for name, dist in (("numpy", "numpy"), ("pillow", "pillow"), ("pytest", "pytest"))}
    prov = [
        "experiment=authenticated-TPE statistical and differential evaluation",
        f"source_commit={git_commit}", f"source_worktree={git_state} at experiment start",
        f"python={sys.version.split()[0]}", *(f"{k}={v}" for k, v in versions.items()),
        f"image_order={','.join(IMAGE_NAMES)}", f"input_dependency=../tpe_rdh_reproduction/input/uct_colour",
        "input_resize=only 256x256 UCT images resized to 512x512 using Pillow Image.resize default; native 512x512 images unchanged",
        "input_file_sha256=" + ";".join(input_hashes),
        f"test_user_key_sha256={sha(TEST_KEY)}", f"flipped_test_user_key_sha256={sha(flipped_key)}",
        f"fixed_test_image_id_sha256={sha(FIXED_ID)}", "ImageID values are not recorded; per-image deterministic fixtures are hashed only",
        "block_size=32; payload=none", "plaintext_delta=top-left R sample per block: +1 unless 255, then -1",
        "key_flip=first key byte XOR 0x01 (exactly one bit)",
        "NPCR=100 * changed sample count / sample count; UACI=100 * sum(abs(int16(A)-int16(B))) / (255 * sample count)",
        "per-channel sample_count=H*W; pooled RGB sample_count=H*W*3 (same pooled formula as original key sensitivity)",
        "commands=.venv/bin/python authenticated_tpe/experiments/run_authenticated_npcr_uaci.py ; see README/report for tests",
        f"script_sha256={sha(Path(__file__).read_bytes())}",
        "interpretation=NPCR/UACI are empirical differential metrics and do not prove cryptographic security",
    ]
    (OUT / "statistical_provenance.txt").write_text("\n".join(prov) + "\n", encoding="utf-8")
    print(f"wrote {OUT / 'npcr_uaci_results.csv'} ({len(plain_rows)} rows)")
    print(f"wrote {OUT / 'key_sensitivity_npcr_uaci.csv'} ({len(key_rows)} rows)")
    print(f"wrote {OUT / 'consistency_hashes.csv'} and {OUT / 'same_key_different_image.csv'}")


if __name__ == "__main__":
    main()
