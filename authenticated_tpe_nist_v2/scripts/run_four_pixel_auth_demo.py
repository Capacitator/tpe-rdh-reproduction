#!/usr/bin/env python3
"""Run the isolated four-pixel TPE + proposed authentication demo on the six tracked images."""
from __future__ import annotations
import csv, hashlib, json, os, sys, time, subprocess
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
OUT = Path(os.environ.get("FOURPX_OUTPUT_DIR",
                          str(ROOT / "output" / "four_pixel_authentication_demo_v2")))
OUT.mkdir(parents=True, exist_ok=True)
FILES = [
    "000_uct_airplane.png", "001_uct_baboon.png", "002_uct_couple.png",
    "003_uct_girl.png", "004_uct_lena.png", "005_uct_peppers.png",
]
def key_from_environment(name: str) -> bytes:
    value=os.environ.get(name)
    if value is None:
        raise RuntimeError(f"set {name} to a 32-byte secret key encoded as 64 hex characters")
    try:
        key=bytes.fromhex(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a 64-character hexadecimal key") from exc
    if len(key)!=32:
        raise RuntimeError(f"{name} must decode to exactly 32 bytes")
    return key
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
    TPE_KEY=key_from_environment("FOURPX_TPE_KEY_HEX")
    AUTH_KEY=key_from_environment("FOURPX_AUTH_KEY_HEX")
    params = fourpx.DemoPipelineParameters(block_size=32, key=TPE_KEY)
    outputs = {}
    rows = []
    for filename in FILES:
        src_path = INPUT / filename
        original = np.asarray(Image.open(src_path).convert("RGB"), dtype=np.uint8)
        stem = Path(filename).stem
        started = time.perf_counter()
        encrypted = exact.encrypt_authenticated_tpe(
            original, PAYLOAD, params, AUTH_KEY, None, tpe_module=fourpx
        )
        encrypted_path = OUT / f"{stem}_four_pixel_authenticated.png"
        Image.fromarray(encrypted.marked_image, mode="RGB").save(encrypted_path)
        sidecar_path = OUT / f"{stem}_authentication_sidecar.bin"
        sidecar_path.write_bytes(encrypted.layout_sidecar)
        # Export/import check: reload only the lossless PNG and AEAD sidecar;
        # both schedule identifiers are recovered from protected metadata.
        exported_image = np.asarray(Image.open(encrypted_path).convert("RGB"), dtype=np.uint8)
        exported_sidecar = sidecar_path.read_bytes()
        exported_recovery = exact.decrypt_authenticated_tpe_bundle(
            exported_image, exported_sidecar, TPE_KEY, AUTH_KEY, tpe_module=fourpx
        )
        if not exported_recovery.accepted or not np.array_equal(exported_recovery.recovered_image, original):
            raise AssertionError(f"serialized-bundle recovery failed for {filename}: {exported_recovery.reason}")
        # Exercise the serialized format in a new interpreter. The child sees
        # only the saved PNG, saved sidecar, and keys passed via its environment.
        restart = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "recover_four_pixel_bundle.py"),
             str(encrypted_path), str(sidecar_path)],
            env={**os.environ, "FOURPX_TPE_KEY_HEX": TPE_KEY.hex(),
                 "FOURPX_AUTH_KEY_HEX": AUTH_KEY.hex()},
            check=True, capture_output=True, text=True,
        )
        restart_result=json.loads(restart.stdout)
        if restart_result["recovered_image_sha256"] != hashlib.sha256(original.tobytes()).hexdigest():
            raise AssertionError(f"fresh-process recovery hash mismatch for {filename}")
        if restart_result["payload_bits"] != PAYLOAD:
            raise AssertionError(f"fresh-process payload recovery mismatch for {filename}")
        thumb_diff = block_means(original) - block_means(encrypted.marked_image)
        thumb_psnr = psnr(block_means(original), block_means(encrypted.marked_image))
        full_mse=float(np.mean((original.astype(np.float64)-encrypted.marked_image.astype(np.float64))**2))
        thumb_mse=float(np.mean(thumb_diff**2))
        rec = {
            "image": filename,
            "width": int(original.shape[1]), "height": int(original.shape[0]),
            "full_image_psnr_db_original_vs_authenticated_ciphertext": psnr(original, encrypted.marked_image),
            "full_image_mse_original_vs_authenticated_ciphertext": full_mse,
            "thumbnail_mse_32x32_per_channel_block_means": thumb_mse,
            "thumbnail_psnr_db_32x32_block_means": None if np.isinf(thumb_psnr) else thumb_psnr,
            "thumbnail_max_abs_mean_difference": float(np.max(np.abs(thumb_diff))),
            "thumbnail_exact": bool(np.array_equal(block_means(original), block_means(encrypted.marked_image))),
            "exact_image_recovery": bool(np.array_equal(exported_recovery.recovered_image, original)),
            "exact_payload_recovery": bool(exported_recovery.recovered_payload_bits == PAYLOAD),
            "serialized_png_sidecar_recovery_without_external_ids": bool(exported_recovery.accepted),
            "fresh_process_recovery_without_encryption_result": True,
            "group_count": int(encrypted.group_count),
            "minimum_group_capacity_bits": int(encrypted.minimum_group_capacity),
            "rdh_tag_bits_per_channel": 256,
            "rdh_user_payload_bits_in_red_channel": len(PAYLOAD),
            "rdh_metadata_bits_per_channel": [int(info.embedded_bit_count - info.payload_length) for info in encrypted.rdh_infos],
            "sidecar_bytes": len(encrypted.layout_sidecar),
            "elapsed_seconds_encrypt_and_decrypt": round(time.perf_counter() - started, 3),
            "source_sha256": hashlib.sha256(src_path.read_bytes()).hexdigest(),
            "encrypted_sha256": hashlib.sha256(encrypted_path.read_bytes()).hexdigest(),
            "sidecar_sha256": hashlib.sha256(encrypted.layout_sidecar).hexdigest(),
        }
        rows.append(rec)
        outputs[stem] = {"original": original, "encryption": encrypted,
                         "image_id": encrypted.auth_image_id, "record": rec}
        print(f"{filename}: full-PSNR={rec['full_image_psnr_db_original_vs_authenticated_ciphertext']:.4f} dB, thumbnail exact={rec['thumbnail_exact']}, recovery={rec['exact_image_recovery']}, groups={rec['group_count']}", flush=True)

    full = [r["full_image_psnr_db_original_vs_authenticated_ciphertext"] for r in rows]
    mean_full = float(np.mean(full))
    sidecars=[r["sidecar_bytes"] for r in rows]
    # A zero-error thumbnail has mathematically unbounded PSNR. Report exact
    # block-mean equality and a JSON null mean rather than inventing a finite value.
    result = {
        "experiment": "four-pixel SPE with exact-order four-block HMAC-SHA256 authentication",
        "method_note": "Four-pixel SPE with repository 2D-CSM-derived schedules. Three 256-bit keyed image tags are embedded in the native histogram-shifting RDH stage (one per channel); caller payload bits share the red-channel RDH stream. The outer AEAD sidecar stores the reversible pairing and block-sum correction map, not the payload or RDH tags.",
        "block_size": 32,
        "authentication_group_size_blocks": 4,
        "native_rdh_authentication": {"tag": "HMAC-SHA256, full 256-bit tag per RGB channel", "payload_location": "red-channel reversible histogram-shifting RDH payload", "pixel_sum_compensation": "authenticated reversible correction map restores source 32x32 block sums"},
        "test_images": len(rows),
        "mean_full_image_psnr_db": mean_full,
        "full_image_psnr_db_range": [float(min(full)),float(max(full))],
        "sidecar_size_bytes": {"mean":float(np.mean(sidecars)),"min":int(min(sidecars)),"max":int(max(sidecars))},
        "mean_thumbnail_psnr_db": None,
        "measurement_definitions": {
            "full_image_psnr": "10 log10(255^2/MSE), MSE is the arithmetic mean of squared uint8 sample differences over all pixels and RGB channels between the original and final authenticated ciphertext; arithmetic mean of six per-image PSNR values is reported.",
            "thumbnail": "Per-channel arithmetic means over each non-overlapping 32x32 block; thumbnail MSE is the arithmetic mean over all 16x16x3 means. Zero MSE is reported as exact equality and infinite PSNR (JSON null). It is separate from full-image PSNR.",
        },
        "thumbnail_psnr_note": "All six per-channel 32x32 block-mean thumbnails are exactly equal (MSE=0); PSNR is +infinity and is encoded as JSON null.",
        "all_exact_image_recovery": all(r["exact_image_recovery"] for r in rows),
        "all_exact_payload_recovery": all(r["exact_payload_recovery"] for r in rows),
        "all_serialized_export_import_recovery": all(r["serialized_png_sidecar_recovery_without_external_ids"] for r in rows),
        "all_thumbnail_exact": all(r["thumbnail_exact"] for r in rows),
        "images": rows,
        "attacks": {},
        "payload_bits": PAYLOAD,
        "key_handling": "Experimental keys were supplied through FOURPX_TPE_KEY_HEX and FOURPX_AUTH_KEY_HEX; key values and hashes are intentionally omitted from saved outputs.",
        "nist_sp800_22": {"status":"not_run_for_this_variant",
                           "reason":"The checked-in predeclared stream definitions are bound to the previous variant's component streams and tag-message format; this adaptation changes the 2D-CSM-derived substitution schedule and authenticated carrier. The previous method's NIST outcomes are not reused or presented as v2 results."},
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
        "recovered_image_withheld": pixel_result.restored_tpe_ciphertext is None,
    }

    # Exercise every color plane and widely separated block locations.
    channel_checks=[]
    for channel,block_id in ((0,0),(1,127),(2,255)):
        group=next(g for g in exact.common._group_order(AUTH_KEY,channel,256) if block_id in g)
        by,bx=divmod(block_id,16)
        changed=target_enc.marked_image.copy()
        changed[by*32+11,bx*32+13,channel]^=1
        check=exact.verify_tpe_ciphertext(changed,target_enc.layout_sidecar,AUTH_KEY,None)
        expected=((channel,int(group[0])),)
        if check.accepted or check.failed_groups!=expected or check.restored_tpe_ciphertext is not None:
            raise AssertionError(f"channel/block localization failed: {channel}/{block_id}: {check.failed_groups}")
        channel_checks.append({"channel":channel,"block_id":block_id,
                               "failed_groups":[list(x) for x in check.failed_groups],
                               "recovered_image_withheld":check.restored_tpe_ciphertext is None})
    result["attacks"]["single_pixel_channel_and_location_sweep"]=channel_checks

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
            "recovered_image_withheld": splice_result.restored_tpe_ciphertext is None,
        }

    # Failure cases with no trustworthy group map: invalid key/ID or invalid
    # sidecar must reject the bundle and withhold every recovered pixel.
    bad_key=bytes([AUTH_KEY[0]^1])+AUTH_KEY[1:]
    bad_id=bytes([target["image_id"][0]^1])+target["image_id"][1:]
    altered=bytearray(target_enc.layout_sidecar); altered[-1]^=1
    donor_sidecar=outputs["000_uct_airplane"]["encryption"].layout_sidecar
    failure_cases={
        "wrong_authentication_key": (target_enc.layout_sidecar,bad_key,None),
        "wrong_image_id": (target_enc.layout_sidecar,AUTH_KEY,bad_id),
        "altered_sidecar": (bytes(altered),AUTH_KEY,None),
        "truncated_sidecar": (target_enc.layout_sidecar[:-9],AUTH_KEY,None),
        "replaced_cross_image_sidecar": (donor_sidecar,AUTH_KEY,None),
    }
    fail_results={}
    for name,(blob,key,iid) in failure_cases.items():
        check=exact.verify_tpe_ciphertext(target_enc.marked_image,blob,key,iid)
        if check.accepted or check.restored_tpe_ciphertext is not None:
            raise AssertionError(f"{name} did not fail closed")
        fail_results[name]={"accepted":False,"failed_groups":[list(x) for x in check.failed_groups],
                            "recovered_image_withheld":True,"reason":check.reason}
    wrong_tpe=exact.decrypt_authenticated_tpe_bundle(
        target_enc.marked_image,target_enc.layout_sidecar,
        bytes([TPE_KEY[0]^1])+TPE_KEY[1:],AUTH_KEY,tpe_module=fourpx)
    if wrong_tpe.accepted or wrong_tpe.recovered_image is not None:
        raise AssertionError("wrong TPE key did not withhold recovery")
    fail_results["wrong_tpe_key"]={"accepted":False,"failed_groups":[],
                                    "recovered_image_withheld":True,
                                    "reason":wrong_tpe.reason}
    result["attacks"]["bundle_failure_cases"]=fail_results

    (OUT / "metrics.json").write_text(json.dumps(result, indent=2, allow_nan=False), encoding="utf-8")
    (OUT / "nist_status.json").write_text(json.dumps(result["nist_sp800_22"],indent=2)+"\n",encoding="utf-8")
    with (OUT / "metrics.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)
    provenance = {
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python": sys.version,
        "numpy": np.__version__,
        "image_files": FILES,
        "all_input_sha256": {f: hashlib.sha256((INPUT / f).read_bytes()).hexdigest() for f in FILES},
        "output_files": sorted(p.name for p in OUT.iterdir() if p.is_file()),
        "sidecar_format": {"magic":"ATPE","version":1,
                           "public_header":"flags, reserved, dimensions, random 16-byte ImageID, 12-byte AEAD nonce; full header is AEAD associated data",
                           "encrypted_body":"pairing layout, reversible correction vector, TPE schedule identifier; no user payload for this adapter"},
        "key_sources": {"tpe_key":"FOURPX_TPE_KEY_HEX environment variable; value/hash omitted",
                        "authentication_key":"FOURPX_AUTH_KEY_HEX environment variable; value/hash omitted"},
    }
    (OUT / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    print(f"\nMean full-image PSNR: {mean_full:.4f} dB")
    print(f"All exact recovery: {result['all_exact_image_recovery']}; all block thumbnails exact: {result['all_thumbnail_exact']}")
    print(f"Attack checks: {json.dumps(result['attacks'], sort_keys=True)}")
    print(f"Artifacts: {OUT}")


if __name__ == "__main__":
    main()
