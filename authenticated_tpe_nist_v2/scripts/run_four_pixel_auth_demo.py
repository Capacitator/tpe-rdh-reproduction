#!/usr/bin/env python3
"""Run the isolated four-pixel TPE + proposed authentication demo on the six tracked images."""
from __future__ import annotations
import csv, hashlib, json, sys, time
from pathlib import Path
import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(REPO / "tpe_rdh_reproduction" / "src"))
import four_pixel_pipeline as fourpx
import block32_exact_order_authenticated_tpe as exact

INPUT = ROOT / "input" / "images_512"
OUT = ROOT / "output" / "four_pixel_authentication_demo"
OUT.mkdir(parents=True, exist_ok=True)
FILES = [
    "000_uct_airplane.png", "001_uct_baboon.png", "002_uct_couple.png",
    "003_uct_girl.png", "004_uct_lena.png", "005_uct_peppers.png",
]
TPE_KEY = hashlib.sha256(b"four-pixel-demo-fixed-tpe-key-v1").digest()
AUTH_KEY = hashlib.sha256(b"four-pixel-demo-fixed-auth-key-v1").digest()
PAYLOAD = [0, 1, 1, 0, 1]


def block_means(img: np.ndarray) -> np.ndarray:
    h, w, _ = img.shape
    if h % 32 or w % 32:
        raise ValueError("demo inputs must have dimensions divisible by 32")
    return img.reshape(h // 32, 32, w // 32, 32, 3).mean(axis=(1, 3), dtype=np.float64)


def psnr(a: np.ndarray, b: np.ndarray) -> float:
    mse = np.mean((a.astype(np.float64) - b.astype(np.float64)) ** 2)
    return float("inf") if mse == 0 else float(10.0 * np.log10(255.0**2 / mse))


def as_hex(items):
    return [int(x) for x in items]


def main() -> None:
    params = fourpx.DemoPipelineParameters(block_size=32, key=TPE_KEY)
    outputs = {}
    rows = []
    for filename in FILES:
        src_path = INPUT / filename
        original = np.asarray(Image.open(src_path).convert("RGB"), dtype=np.uint8)
        stem = Path(filename).stem
        image_id = hashlib.sha256(b"four-pixel-image-id-v1\x00" + filename.encode() + original.tobytes()).digest()[:16]
        started = time.perf_counter()
        encrypted = exact.encrypt_authenticated_tpe(
            original, PAYLOAD, params, AUTH_KEY, image_id, tpe_module=fourpx
        )
        recovered = exact.decrypt_authenticated_tpe(
            encrypted.marked_image, encrypted.layout_sidecar, params,
            AUTH_KEY, image_id, encrypted.tpe_image_identifier, PAYLOAD,
            tpe_module=fourpx,
        )
        if not recovered.accepted or not np.array_equal(recovered.recovered_image, original):
            raise AssertionError(f"exact recovery failed for {filename}: {recovered.reason}")
        if recovered.recovered_payload_bits != PAYLOAD:
            raise AssertionError(f"payload recovery failed for {filename}")
        encrypted_path = OUT / f"{stem}_four_pixel_authenticated.png"
        Image.fromarray(encrypted.marked_image, mode="RGB").save(encrypted_path)
        sidecar_path = OUT / f"{stem}_authentication_sidecar.bin"
        sidecar_path.write_bytes(encrypted.layout_sidecar)
        thumb_diff = block_means(original) - block_means(encrypted.marked_image)
        thumb_psnr = psnr(block_means(original), block_means(encrypted.marked_image))
        rec = {
            "image": filename,
            "width": int(original.shape[1]), "height": int(original.shape[0]),
            "full_image_psnr_db_original_vs_authenticated_ciphertext": psnr(original, encrypted.marked_image),
            "thumbnail_psnr_db_32x32_block_means": None if np.isinf(thumb_psnr) else thumb_psnr,
            "thumbnail_max_abs_mean_difference": float(np.max(np.abs(thumb_diff))),
            "thumbnail_exact": bool(np.array_equal(block_means(original), block_means(encrypted.marked_image))),
            "exact_image_recovery": bool(np.array_equal(recovered.recovered_image, original)),
            "exact_payload_recovery": bool(recovered.recovered_payload_bits == PAYLOAD),
            "group_count": int(encrypted.group_count),
            "minimum_group_capacity_bits": int(encrypted.minimum_group_capacity),
            "sidecar_bytes": len(encrypted.layout_sidecar),
            "elapsed_seconds_encrypt_and_decrypt": round(time.perf_counter() - started, 3),
            "source_sha256": hashlib.sha256(src_path.read_bytes()).hexdigest(),
            "encrypted_sha256": hashlib.sha256(encrypted_path.read_bytes()).hexdigest(),
            "sidecar_sha256": hashlib.sha256(encrypted.layout_sidecar).hexdigest(),
        }
        rows.append(rec)
        outputs[stem] = {"original": original, "encryption": encrypted, "image_id": image_id, "record": rec}
        print(f"{filename}: full-PSNR={rec['full_image_psnr_db_original_vs_authenticated_ciphertext']:.4f} dB, thumbnail exact={rec['thumbnail_exact']}, recovery={rec['exact_image_recovery']}, groups={rec['group_count']}", flush=True)

    full = [r["full_image_psnr_db_original_vs_authenticated_ciphertext"] for r in rows]
    mean_full = float(np.mean(full))
    # A zero-error thumbnail has mathematically unbounded PSNR. Report exact
    # block-mean equality and a JSON null mean rather than inventing a finite value.
    result = {
        "experiment": "four-pixel SPE with exact-order four-block HMAC-SHA256 authentication",
        "method_note": "Four-pixel SPE paper transform with repository 2D-CSM-derived schedules; caller payload protected in the existing AEAD sidecar because the SPE paper does not specify payload carriage.",
        "block_size": 32,
        "authentication_group_size_blocks": 4,
        "test_images": len(rows),
        "mean_full_image_psnr_db": mean_full,
        "mean_thumbnail_psnr_db": None,
        "thumbnail_psnr_note": "All six 32x32 block-mean thumbnails are bit-exact (zero MSE); PSNR is mathematically infinite/undefined as a finite average.",
        "all_exact_image_recovery": all(r["exact_image_recovery"] for r in rows),
        "all_exact_payload_recovery": all(r["exact_payload_recovery"] for r in rows),
        "all_thumbnail_exact": all(r["thumbnail_exact"] for r in rows),
        "images": rows,
        "attacks": {},
        "fixture_key_sha256": {"tpe_key": hashlib.sha256(TPE_KEY).hexdigest(), "auth_key": hashlib.sha256(AUTH_KEY).hexdigest()},
        "payload_bits": PAYLOAD,
    }

    # One-pixel edit in a known four-block authentication group.
    target = outputs["004_uct_lena"]
    target_enc = target["encryption"]
    channel = 1
    group = exact.common._group_order(AUTH_KEY, channel, 256)[0]
    block_id = group[0]
    by, bx = divmod(block_id, 16)
    pixel = target_enc.marked_image.copy()
    pixel[by * 32 + 7, bx * 32 + 9, channel] ^= 1
    pixel_result = exact.verify_tpe_ciphertext(pixel, target_enc.layout_sidecar, AUTH_KEY, target["image_id"])
    expected_label = (channel, int(group[0]))
    if pixel_result.accepted or pixel_result.failed_groups != (expected_label,):
        raise AssertionError(f"one-pixel localization mismatch: expected {expected_label}, got {pixel_result.failed_groups}")
    result["attacks"]["one_pixel_change"] = {
        "target": "004_uct_lena.png", "channel": channel,
        "coordinate_yx": [int(by * 32 + 7), int(bx * 32 + 9)],
        "changed_pixel_count": 1, "accepted": pixel_result.accepted,
        "failed_group_label": [channel, int(group[0])],
        "failed_group_block_ids": as_hex(group),
        "localized_group_count": len(pixel_result.failed_groups),
    }

    # Cross-image substitutions in both directions; the destination sidecar/key
    # and image ID remain unchanged, and one complete 32x32 ciphertext block is replaced.
    for target_name, donor_name, block_id in [
        ("004_uct_lena", "000_uct_airplane", 5),
        ("000_uct_airplane", "004_uct_lena", 42),
    ]:
        t = outputs[target_name]
        d = outputs[donor_name]
        t_enc, d_enc = t["encryption"], d["encryption"]
        by, bx = divmod(block_id, 16)
        splice = t_enc.marked_image.copy()
        y0, x0 = by * 32, bx * 32
        splice[y0:y0 + 32, x0:x0 + 32, :] = d_enc.marked_image[y0:y0 + 32, x0:x0 + 32, :]
        splice_result = exact.verify_tpe_ciphertext(splice, t_enc.layout_sidecar, AUTH_KEY, t["image_id"])
        expected_groups = []
        for c in range(3):
            group = next(g for g in exact.common._group_order(AUTH_KEY, c, 256) if block_id in g)
            expected_groups.append((c, int(group[0])))
        expected_groups = tuple(sorted(expected_groups))
        if splice_result.accepted or tuple(sorted(splice_result.failed_groups)) != expected_groups:
            raise AssertionError(f"splice localization mismatch {donor_name}->{target_name} block {block_id}: expected {expected_groups}, got {splice_result.failed_groups}")
        group_members = {
            str(c): as_hex(next(g for g in exact.common._group_order(AUTH_KEY, c, 256) if block_id in g))
            for c in range(3)
        }
        result["attacks"][f"splice_{donor_name}_to_{target_name}"] = {
            "donor": donor_name + ".png", "target": target_name + ".png",
            "replaced_ciphertext_block_id": block_id,
            "replaced_region_yxhw": [int(y0), int(x0), 32, 32],
            "failed_group_labels_by_channel": [[c, label] for c, label in expected_groups],
            "failed_group_block_ids_by_channel": group_members,
            "localized_group_count": len(splice_result.failed_groups),
            "accepted": splice_result.accepted,
        }

    (OUT / "metrics.json").write_text(json.dumps(result, indent=2, allow_nan=False), encoding="utf-8")
    with (OUT / "metrics.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader(); writer.writerows(rows)
    provenance = {
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python": sys.version,
        "numpy": np.__version__,
        "image_files": FILES,
        "all_input_sha256": {f: hashlib.sha256((INPUT / f).read_bytes()).hexdigest() for f in FILES},
        "output_files": sorted(p.name for p in OUT.iterdir() if p.is_file()),
    }
    (OUT / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    print(f"\nMean full-image PSNR: {mean_full:.4f} dB")
    print(f"All exact recovery: {result['all_exact_image_recovery']}; all block thumbnails exact: {result['all_thumbnail_exact']}")
    print(f"Attack checks: {json.dumps(result['attacks'], sort_keys=True)}")
    print(f"Artifacts: {OUT}")


if __name__ == "__main__":
    main()
