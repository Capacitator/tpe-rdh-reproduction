#!/usr/bin/env python3
"""Test actual block-r1 2-bit outputs with official NIST STS 2.1.2.

This is an additive, separately labeled experiment. It preserves the existing
NIST campaign that tests full HMAC digests and does not change the cipher.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
V2_ROOT = REPO / "authenticated_tpe_nist_v2"
sys.path.insert(0, str(V2_ROOT / "src"))
import atpe_v2 as v2  # noqa: E402
import nist_runner as nist  # noqa: E402

BITS = 1_000_000
BYTES = BITS // 8
VALUES_PER_STREAM = BITS // 2
VALUES_PER_KEY = 3 * 256
KEYS_PER_STREAM = (VALUES_PER_STREAM + VALUES_PER_KEY - 1) // VALUES_PER_KEY
KEY_BASE = 10_000
COUNT = 100
CATEGORY = "block_r1_actual_output"
OUT = ROOT / "output"


def pool_key(index: int) -> bytes:
    if not 0 <= index < 1 << 32:
        raise ValueError("key index must fit u32")
    return hashlib.sha256(b"atpe-v2|userkey|" + index.to_bytes(4, "big")).digest()


def set_two_bits(buf: bytearray, value_index: int, value: int) -> None:
    """Pack r1=0..3 values in execution order, MSB-first, four values/byte."""
    if not 0 <= value <= 3:
        raise ValueError("r1 must be in 0..3")
    byte_index = value_index >> 2
    shift = 6 - 2 * (value_index & 3)
    buf[byte_index] |= value << shift


def build_stream(stream_index: int) -> tuple[bytes, dict]:
    if not 1 <= stream_index <= COUNT:
        raise ValueError("stream index must be in 1..100")
    out = bytearray(BYTES)
    value_index = 0
    first_key = KEY_BASE + (stream_index - 1) * KEYS_PER_STREAM
    used_key_hashes = hashlib.sha256()
    used_keys = 0
    for slot in range(KEYS_PER_STREAM):
        key_index = first_key + slot
        user_key = pool_key(key_index)
        used_key_hashes.update(user_key)
        used_keys += 1
        kr1 = [v2.derive_keys(user_key, channel)["Kr1"] for channel in range(3)]
        for channel in range(3):
            for block_id in range(256):
                if value_index == VALUES_PER_STREAM:
                    break
                # Use the cipher's actual r1 function, including digest parsing
                # and modulo-four reduction; do not feed a raw digest here.
                r1 = v2.block_r1(kr1[channel], block_id)
                set_two_bits(out, value_index, r1)
                value_index += 1
            if value_index == VALUES_PER_STREAM:
                break
        if value_index == VALUES_PER_STREAM:
            break
    if value_index != VALUES_PER_STREAM or len(out) != BYTES:
        raise AssertionError(f"wrong stream size: values={value_index}, bytes={len(out)}")
    return bytes(out), {
        "category": CATEGORY,
        "stream_index": stream_index,
        "stream_bits": BITS,
        "stream_bytes": BYTES,
        "r1_values": VALUES_PER_STREAM,
        "packing": "two-bit r1 symbols, four per byte, MSB-first; channel then block order",
        "user_key_index_start": first_key,
        "user_key_index_end_inclusive": first_key + used_keys - 1,
        "user_keys_used": used_keys,
        "user_keys_sha256_in_order": used_key_hashes.hexdigest(),
        "stream_sha256": hashlib.sha256(out).hexdigest(),
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("\n", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_streams() -> list[dict]:
    stream_dir = OUT / "streams"
    stream_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    seen = set()
    for i in range(1, COUNT + 1):
        data, meta = build_stream(i)
        if meta["stream_sha256"] in seen:
            raise AssertionError("duplicate actual-r1 stream")
        seen.add(meta["stream_sha256"])
        path = stream_dir / f"{CATEGORY}_{i:03d}.bin"
        path.write_bytes(data)
        meta["path"] = str(path.relative_to(ROOT))
        rows.append(meta)
        if i % 10 == 0:
            print(f"[streams] {i}/{COUNT} actual-r1 streams generated", flush=True)
    write_csv(OUT / "stream_manifest.csv", rows)
    return rows


def run_nist(sts_root: Path, streams: list[dict]) -> None:
    ascii_path = OUT / "nist_input" / f"{CATEGORY}_ascii.txt"
    ascii_path.parent.mkdir(parents=True, exist_ok=True)
    with ascii_path.open("w", encoding="ascii") as f:
        for row in streams:
            data = (ROOT / row["path"]).read_bytes()
            if len(data) != BYTES:
                raise AssertionError(f"bad stream byte count in {row['path']}")
            f.write("".join(f"{b:08b}" for b in data))
            f.write("\n")
    tree = Path("/home/ubuntu/work/sts_runs/r1_actual_output")
    if tree.exists():
        shutil.rmtree(tree)
    tree.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(sts_root, tree)
    nist.clean_results(tree)
    log_path = OUT / "nist_logs" / f"{CATEGORY}_assess_stdout.txt"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    nist.run_assess(tree, ascii_path, COUNT, BITS, log_path)
    raw = nist.collect_reports(tree, OUT, CATEGORY)["raw_dir"]
    first, warnings = nist.parse_first_level(raw, COUNT)
    second = nist.parse_second_level(raw / "finalAnalysisReport.txt")
    summary = nist.summarise(first, 0.01)

    first_rows = [{
        "test_name": r["test_name"], "test_label": r["test_label"],
        "stream_index": r["stream_index"], "component": r["component_label"],
        "p_value": "" if r["p_value"] is None else f"{r['p_value']:.12g}",
        "status": "not-applicable" if r["p_value"] is None else ("pass" if r["p_value"] >= .01 else "fail"),
        "alpha": .01,
    } for r in first]
    write_csv(OUT / "first_level_pvalues.csv", first_rows)
    second_rows = []
    for r in second:
        second_rows.append({
            "test_name": r["test"], "component": r.get("recomputed_component", ""),
            **{f"C{i+1}": r["bins"][i] for i in range(10)},
            "suite_p_value": r["report_p_value"],
            "recomputed_chi_square": "" if r["chi_square"] is None else f"{r['chi_square']:.12g}",
            "recomputed_uniformity_p_value": "" if r["uniformity_p_value"] is None else f"{r['uniformity_p_value']:.12g}",
            "nist_uniformity_threshold": .0001,
        })
    write_csv(OUT / "second_level_uniformity.csv", second_rows)
    write_csv(OUT / "summary_counts.csv", summary)
    hashes = [{"path": str(p.relative_to(ROOT)), "sha256": sha256_file(p)}
              for p in sorted(raw.rglob("*")) if p.is_file()]
    write_csv(OUT / "raw_report_manifest.csv", hashes)
    (OUT / "parse_warnings.txt").write_text("\n".join(warnings) + ("\n" if warnings else "none\n"), encoding="utf-8")

    pvalid = [r for r in second if r["uniformity_p_value"] is not None]
    p_fail = sum(r["uniformity_p_value"] < .0001 for r in pvalid)
    first_pass = sum(r["p_value"] is not None and r["p_value"] >= .01 for r in first)
    first_fail = sum(r["p_value"] is not None and r["p_value"] < .01 for r in first)
    first_na = sum(r["p_value"] is None for r in first)
    (OUT / "summary.md").write_text(
        "# Actual block-r1 output: NIST STS results\n\n"
        "This is a separate supplemental run on the cipher-consumed r1 symbols, not a replacement for the existing raw-HMAC-digest campaign.\n\n"
        f"- Streams: {COUNT}; bits per stream: {BITS:,}; first-level alpha: 0.01.\n"
        f"- First-level values: pass {first_pass}, fail {first_fail}, N/A {first_na}.\n"
        f"- Second-level uniformity: {len(pvalid)} valid component p-values; {p_fail} below NIST's 0.0001 threshold.\n"
        "- All per-stream p-values and official raw reports are retained alongside SHA-256 manifests.\n\n"
        "A low first-level p-value is kept as a failure at alpha=0.01; no streams are removed or selected. N/A is retained for tests whose STS applicability conditions are not met.\n",
        encoding="utf-8")
    sts_patch = Path("/home/ubuntu/work/sts/sts_build.patch")
    provenance = [
        f"sts_dir={sts_root}", f"sts_binary_sha256={sha256_file(sts_root / 'assess')}",
        f"sts_patch_sha256={sha256_file(sts_patch)}" if sts_patch.is_file() else "sts_patch_sha256=missing",
        f"generator_sha256={sha256_file(Path(__file__))}",
        f"stream_manifest_sha256={sha256_file(OUT / 'stream_manifest.csv')}",
        f"protocol=official NIST STS 2.1.2 assess; {COUNT} streams x {BITS} bits; all default tests; ASCII mode",
        "r1_definition=actual authenticated_tpe.block_r1: int.from_bytes(HMAC-SHA256(Kr1_c, b'r1'||u16be(block_id))[:4], 'big') % 4",
        f"packing=2-bit r1 symbols packed MSB-first; {VALUES_PER_STREAM} symbols per stream",
        f"keys=SHA256(b'atpe-v2|userkey|'||u32be(index)); disjoint indices {KEY_BASE}..{KEY_BASE+COUNT*KEYS_PER_STREAM-1}",
    ]
    (OUT / "provenance.txt").write_text("\n".join(provenance) + "\n", encoding="utf-8")
    print(f"[done] first-level P/F/N-A={first_pass}/{first_fail}/{first_na}; "
          f"second-level uniformity failures={p_fail}/{len(pvalid)}", flush=True)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--sts-dir", type=Path, required=True)
    p.add_argument("--skip-generation", action="store_true")
    args = p.parse_args()
    if args.skip_generation:
        with (OUT / "stream_manifest.csv").open(newline="", encoding="utf-8") as f:
            streams = list(csv.DictReader(f))
        if len(streams) != COUNT:
            raise RuntimeError("manifest does not contain exactly 100 streams")
    else:
        streams = generate_streams()
    run_nist(args.sts_dir.resolve(), streams)

if __name__ == "__main__":
    main()
