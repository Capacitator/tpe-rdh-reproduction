#!/usr/bin/env python3
"""Run a separated NIST SP 800-22 evaluation for authenticated-TPE.

This runner creates four cryptographic-component categories and retains the
two established image-output diagnostics. It feeds the official STS binary
packed bytes (MSB-first), one million bits per stream, with no padding.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np
from PIL import Image, __version__ as pillow_version

PROJECT = Path(__file__).resolve().parents[1]
REPO = PROJECT.parent
OUT = PROJECT / "output" / "nist_sp800_22_improved"
UCT = REPO / "tpe_rdh_reproduction" / "input" / "uct_colour"
N_STREAMS = 100
STREAM_BITS = 1_000_000
STREAM_BYTES = STREAM_BITS // 8
ALPHA = 0.01
IMAGES = ("airplane", "baboon", "couple", "girl", "lena", "peppers")
TEST_NAMES = (
    "Frequency", "BlockFrequency", "CumulativeSums", "Runs", "LongestRun",
    "Rank", "FFT", "NonOverlappingTemplate", "OverlappingTemplate",
    "Universal", "ApproximateEntropy", "RandomExcursions",
    "RandomExcursionsVariant", "Serial", "LinearComplexity",
)
COMPONENT_COUNTS = {
    "Frequency": 1, "BlockFrequency": 1, "CumulativeSums": 2, "Runs": 1,
    "LongestRun": 1, "Rank": 1, "FFT": 1, "NonOverlappingTemplate": 148,
    "OverlappingTemplate": 1, "Universal": 1, "ApproximateEntropy": 1,
    "RandomExcursions": 8, "RandomExcursionsVariant": 18, "Serial": 2,
    "LinearComplexity": 1,
}
CATEGORIES = (
    "cryptographic_hmac_drbg",
    "cryptographic_pair_shift_words",
    "cryptographic_block_r1_values",
    "authentication_tag_stream",
    "image_output_step2",
    "image_output_final_marked",
)
BIT_TEXT = tuple(f"{v:08b}".encode("ascii") for v in range(256))
REPORT_LINE = re.compile(
    r"^\s*(?:\d+\s+){10}(?P<uniformity>\d+\.\d+|----)\s+\*?\s*"
    r"(?P<proportion>\d+/\d+|------)\s+\*?\s*(?P<test>[A-Za-z]+)\s*$"
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture(domain: bytes, index: int, length: int) -> bytes:
    """Deterministic public test fixtures; never use these as production keys."""
    return hashlib.sha256(domain + b"\x00" + index.to_bytes(8, "big")).digest()[:length]


def old_fixture(domain: bytes, index: int, length: int) -> bytes:
    """Reproduce the fixture rule from the prior authenticated-TPE NIST run."""
    return hashlib.sha256(domain + b"\x00" + index.to_bytes(4, "big")).digest()[:length]


def bit_ascii_hash(data: bytes) -> str:
    return sha(b"".join(BIT_TEXT[value] for value in data))


def row_writer(path: Path, rows: list[dict], fields: list[str] | None = None) -> None:
    if fields is None:
        fields = list(dict.fromkeys(key for row in rows for key in row)) if rows else []
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def load_image(name: str) -> tuple[np.ndarray, str]:
    source = UCT / f"{name}.tif"
    source_hash = sha(source.read_bytes())
    with Image.open(source) as image:
        image = image.convert("RGB")
        if image.size != (512, 512):
            image = image.resize((512, 512))
        arr = np.asarray(image, dtype=np.uint8)
    if arr.shape != (512, 512, 3) or arr.dtype != np.uint8:
        raise AssertionError(f"Unexpected normalized image shape for {name}")
    return np.ascontiguousarray(arr), source_hash


def previous_manifest() -> dict[tuple[str, int], dict[str, str]]:
    path = OUT / "stream_manifest.csv"
    if not path.is_file():
        return {}
    with path.open(newline="", encoding="utf-8") as f:
        data = list(csv.DictReader(f))
    return {(r["image"], int(r["stream_index"])): r for r in data}


def generate_streams() -> tuple[list[dict], list[dict], list[dict]]:
    sys.path.insert(0, str(PROJECT / "src"))
    import authenticated_tpe as auth

    old = previous_manifest()
    raw_root = OUT / "raw_streams"
    shutil.rmtree(raw_root, ignore_errors=True)
    raw_root.mkdir(parents=True, exist_ok=True)
    handles = {}
    for category in CATEGORIES:
        dest = raw_root / category
        dest.mkdir(parents=True, exist_ok=True)
        handles[category] = (dest / "input.bin").open("wb")

    manifest: list[dict] = []
    context_rows: list[dict] = []
    recovery_rows: list[dict] = []
    seen_hashes: set[str] = set()
    image_cache = {name: load_image(name) for name in IMAGES}
    image_normalized_hashes = {n: sha(a.tobytes(order="C")) for n, (a, _) in image_cache.items()}

    def record(category: str, index: int, payload: bytes, source: str, **fields: object) -> None:
        if len(payload) != STREAM_BYTES:
            raise AssertionError(f"{category} stream {index} is {len(payload) * 8} bits")
        digest = sha(payload)
        if digest in seen_hashes:
            raise AssertionError(f"Duplicate raw stream detected: {category} #{index}")
        seen_hashes.add(digest)
        handles[category].write(payload)
        manifest.append({
            "category": category,
            "stream_index": index,
            "image_or_source": source,
            "stream_length_bits": STREAM_BITS,
            "raw_stream_file": f"raw_streams/{category}/input.bin",
            "byte_offset": (index - 1) * STREAM_BYTES,
            "stream_bytes": STREAM_BYTES,
            "stream_sha256": digest,
            "serialization": "MSB-first packed bits; NIST consumes each byte high bit first",
            **fields,
        })

    # A: The exact HMAC-DRBG state machine used by group_blocks. Each stream is
    # expanded by successive 4-byte Generate calls, matching the implementation.
    for i in range(1, N_STREAMS + 1):
        entropy = fixture(b"authenticated-tpe-nist-hmac-drbg-entropy-v1", i, 32)
        nonce = fixture(b"authenticated-tpe-nist-hmac-drbg-nonce-v1", i, 16)
        drbg = auth.HMACDRBG(entropy, nonce, b"group-perm")
        out = bytearray()
        for _ in range(STREAM_BITS // 32):
            out.extend(drbg.generate4().to_bytes(4, "big"))
        record(
            "cryptographic_hmac_drbg", i, bytes(out), "HMAC_DRBG group-permutation generator",
            entropy_input_sha256=sha(entropy), nonce_sha256=sha(nonce),
            entropy_domain="authenticated-tpe-nist-hmac-drbg-entropy-v1",
            nonce_domain="authenticated-tpe-nist-hmac-drbg-nonce-v1",
            personalization="group-perm", generate_call_bytes=4,
            independent_fixture_index=i,
        )
        if i % 10 == 0:
            print(f"generated HMAC-DRBG streams: {i}/{N_STREAMS}", flush=True)

    # B: The first 32 bits of the exact HMAC digest consumed by pair_shift,
    # before its class-size modulo. Valid channel/block/pair indices are visited
    # once each in the implementation's index ranges; no image bytes are used.
    for i in range(1, N_STREAMS + 1):
        user_key = fixture(b"authenticated-tpe-nist-pair-key-v1", i, 32)
        image_id = fixture(b"authenticated-tpe-nist-pair-image-id-v1", i, 16)
        out = bytearray()
        used = 0
        for channel in range(3):
            ktpe = auth.derive_keys(user_key, channel)["Ktpe"]
            for block_id in range(auth.BLOCK_COUNT):
                for pair_index in range(auth.PAIRS_PER_BLOCK):
                    msg = b"tpe-shift" + image_id + block_id.to_bytes(2, "big") + pair_index.to_bytes(2, "big")
                    out.extend(__import__("hmac").new(ktpe, msg, hashlib.sha256).digest()[:4])
                    used += 1
                    if used == STREAM_BITS // 32:
                        break
                if used == STREAM_BITS // 32:
                    break
            if used == STREAM_BITS // 32:
                break
        record(
            "cryptographic_pair_shift_words", i, bytes(out), "raw 32-bit HMAC words used by pair_shift",
            user_key_sha256=sha(user_key), image_id_sha256=sha(image_id),
            user_key_domain="authenticated-tpe-nist-pair-key-v1",
            image_id_domain="authenticated-tpe-nist-pair-image-id-v1",
            hmac_input_rule="b'tpe-shift'||ImageID||u16be(block_id)||u16be(pair_index)",
            sampled_distinct_pair_inputs=used,
        )
        if i % 10 == 0:
            print(f"generated pair-shift streams: {i}/{N_STREAMS}", flush=True)

    # C: Exact two-bit block_r1 outcomes. Each NIST stream concatenates values
    # in channel/block order across independent UserKeys. This explicit expansion
    # is necessary because one image supplies only 768 two-bit r1 values.
    r1_values_per_context = auth.CHANNELS * auth.BLOCK_COUNT
    r1_contexts_per_stream = (STREAM_BITS // 2 + r1_values_per_context - 1) // r1_values_per_context
    expected_r1_values = STREAM_BITS // 2
    for i in range(1, N_STREAMS + 1):
        out = bytearray()
        context_key_digests = []
        packed_values: list[int] = []
        values_used = 0
        for context in range(r1_contexts_per_stream):
            global_index = (i - 1) * r1_contexts_per_stream + context + 1
            user_key = fixture(b"authenticated-tpe-nist-r1-key-v1", global_index, 32)
            context_key_digests.append(sha(user_key))
            for channel in range(auth.CHANNELS):
                kr1 = auth.derive_keys(user_key, channel)["Kr1"]
                for block_id in range(auth.BLOCK_COUNT):
                    if values_used == expected_r1_values:
                        break
                    packed_values.append(auth.block_r1(kr1, block_id))
                    values_used += 1
                    if len(packed_values) == 4:
                        out.append((packed_values[0] << 6) | (packed_values[1] << 4) | (packed_values[2] << 2) | packed_values[3])
                        packed_values.clear()
                if values_used == expected_r1_values:
                    break
            context_rows.append({
                "category": "cryptographic_block_r1_values",
                "stream_index": i,
                "context_index": context + 1,
                "user_key_sha256": sha(user_key),
                "user_key_domain": "authenticated-tpe-nist-r1-key-v1",
                "fixture_index": global_index,
                "image_id": "not-used-by-block_r1",
                "channels_emitted": "0,1,2" if context + 1 < r1_contexts_per_stream else "prefix as needed",
            })
            if values_used == expected_r1_values:
                break
        if packed_values or values_used != expected_r1_values:
            raise AssertionError("r1 stream packing failed")
        context_set_hash = sha("\n".join(context_key_digests).encode("ascii"))
        record(
            "cryptographic_block_r1_values", i, bytes(out),
            "2-bit block_r1 outcomes across independent key contexts",
            context_count=len(context_key_digests), context_user_key_set_sha256=context_set_hash,
            r1_values_per_stream=values_used,
            r1_order="context index, channel 0..2, block ID 0..255; each r1 as two MSB-first bits",
        )
        if i % 10 == 0:
            print(f"generated block-r1 streams: {i}/{N_STREAMS}", flush=True)

    # D: Isolated raw HMAC group-tag diagnostic across independent key/ImageID pairs.
    tags_per_context = auth.CHANNELS * auth.GROUPS_PER_CHANNEL
    tag_contexts_per_stream = (STREAM_BITS + tags_per_context * auth.TAG_BITS - 1) // (tags_per_context * auth.TAG_BITS)
    tag_fixture_images = {}
    for fixture_index, name in enumerate(IMAGES, 1):
        ref_image, _ = image_cache[name]
        ref_key = fixture(b"authenticated-tpe-nist-tag-reference-key-v1", fixture_index, 32)
        ref_id = fixture(b"authenticated-tpe-nist-tag-reference-id-v1", fixture_index, 16)
        step1_ref = auth._step1_image(ref_image, ref_key, ref_id)
        tag_fixture_images[name] = (step1_ref, sha(step1_ref.tobytes(order="C")))
    for i in range(1, N_STREAMS + 1):
        out = bytearray()
        tag_context_digests = []
        for context in range(tag_contexts_per_stream):
            global_index = (i - 1) * tag_contexts_per_stream + context + 1
            user_key = fixture(b"authenticated-tpe-nist-tag-key-v1", global_index, 32)
            image_id = fixture(b"authenticated-tpe-nist-tag-image-id-v1", global_index, 16)
            name = IMAGES[(global_index - 1) % len(IMAGES)]
            step1_ref, step1_hash = tag_fixture_images[name]
            for channel in range(auth.CHANNELS):
                kstruct = auth.derive_keys(user_key, channel)["Kstruct"]
                for block_ids in auth.group_blocks(kstruct):
                    out.extend(auth._group_mac(step1_ref, user_key, image_id, channel, block_ids))
            context_rows.append({
                "category": "authentication_tag_stream", "stream_index": i,
                "context_index": context + 1, "fixture_index": global_index,
                "user_key_sha256": sha(user_key), "image_id_sha256": sha(image_id),
                "user_key_domain": "authenticated-tpe-nist-tag-key-v1",
                "image_id_domain": "authenticated-tpe-nist-tag-image-id-v1",
                "step1_reference_image": name, "step1_reference_array_sha256": step1_hash,
                "tags_generated": tags_per_context,
            })
            tag_context_digests.append(sha(user_key) + sha(image_id))
        record("authentication_tag_stream", i, bytes(out[:STREAM_BYTES]),
               "raw 256-bit HMAC-SHA256 group authentication tags",
               context_count=tag_contexts_per_stream,
               context_key_imageid_set_sha256=sha("\n".join(tag_context_digests).encode("ascii")),
               tags_generated=tag_contexts_per_stream * tags_per_context,
               tag_order="context, channel 0..2, authenticated group order; raw tags MSB-first",
               reference_data="fixed public Step-1 image fixtures; isolated HMAC tag component diagnostic")
        if i % 10 == 0:
            print(f"generated authentication-tag streams: {i}/{N_STREAMS}", flush=True)

    # E/F: Preserve the prior deterministic key/ImageID fixture exactly so the
    # image diagnosis can be compared to the already-published experiment.
    for i in range(1, N_STREAMS + 1):
        name = IMAGES[(i - 1) % len(IMAGES)]
        image, source_hash = image_cache[name]
        user_key = old_fixture(b"auth-tpe-nist-key-v1", i, 32)
        image_id = old_fixture(b"auth-tpe-nist-image-id-v1", i, 16)
        step1 = auth._step1_image(image, user_key, image_id)
        step2 = auth._step2_image(step1, user_key)
        protected = auth.protect_image(image, user_key, image_id)
        verified = auth.verify_and_decrypt(protected.marked_image, user_key, image_id)
        exact = bool(verified.accepted and np.array_equal(verified.recovered_image, image))
        if not exact:
            raise AssertionError(f"Exact recovery failed for image stream {i} ({name})")
        step2_raw = step2.tobytes(order="C")[:STREAM_BYTES]
        marked_raw = protected.marked_image.tobytes(order="C")[:STREAM_BYTES]
        old_step2 = old.get((name, i), {})
        old_final = old.get((name, i), {})
        step2_ascii_hash = bit_ascii_hash(step2_raw)
        marked_ascii_hash = bit_ascii_hash(marked_raw)
        step2_match = step2_ascii_hash == old_step2.get("step2_stream_sha256", "")
        marked_match = marked_ascii_hash == old_final.get("final_marked_stream_sha256", "")
        if old and not (step2_match and marked_match):
            raise AssertionError(f"Reconstructed stream disagrees with prior manifest for {name} #{i}")
        if old:
            checks = (
                (old_step2.get("source_image_sha256"), source_hash, "source image"),
                (old_step2.get("user_key_sha256"), sha(user_key), "UserKey"),
                (old_step2.get("image_id_sha256"), sha(image_id), "ImageID"),
                (old_step2.get("step2_sha256"), sha(step2.tobytes(order="C")), "Step-2 array"),
                (old_final.get("final_marked_image_sha256"), sha(protected.marked_image.tobytes(order="C")), "marked array"),
            )
            for prior, current, label in checks:
                if prior and prior != current:
                    raise AssertionError(f"Prior {label} hash mismatch for {name} #{i}")
        common = dict(
            image=name, source_image_sha256=source_hash,
            normalized_image_sha256=image_normalized_hashes[name],
            user_key_sha256=sha(user_key), image_id_sha256=sha(image_id),
            user_key_domain="auth-tpe-nist-key-v1 (legacy deterministic fixture)",
            image_id_domain="auth-tpe-nist-image-id-v1 (legacy deterministic fixture)",
            authentication_accepted=verified.accepted, exact_recovery=exact,
        )
        record("image_output_step2", i, step2_raw, f"UCT {name}; Step-2 image-derived keyed intermediate", **common,
               tested_array_sha256=sha(step2.tobytes(order="C")), previous_ascii_bitstream_sha256=step2_ascii_hash,
               previous_run_hash_match=step2_match)
        record("image_output_final_marked", i, marked_raw, f"UCT {name}; final marked RGB", **common,
               tested_array_sha256=sha(protected.marked_image.tobytes(order="C")), previous_ascii_bitstream_sha256=marked_ascii_hash,
               previous_run_hash_match=marked_match)
        recovery_rows.append({
            "image": name, "stream_index": i, "source_image_sha256": source_hash,
            "user_key_sha256": sha(user_key), "image_id_sha256": sha(image_id),
            "authentication_accepted": verified.accepted, "exact_recovery": exact,
            "mode": protected.mode, "groups": protected.embedded_tags,
            "pairs_used": protected.pairs_used,
        })
        if i % 5 == 0:
            print(f"generated and verified image streams: {i}/{N_STREAMS}", flush=True)

    for handle in handles.values():
        handle.close()
    if len(seen_hashes) != len(CATEGORIES) * N_STREAMS:
        raise AssertionError("Stream uniqueness check failed")
    for category in CATEGORIES:
        rows = [r for r in manifest if r["category"] == category]
        if len({r["stream_sha256"] for r in rows}) != N_STREAMS:
            raise AssertionError(f"Duplicate streams within category {category}")
    drbg_rows = [r for r in manifest if r["category"] == "cryptographic_hmac_drbg"]
    pair_rows = [r for r in manifest if r["category"] == "cryptographic_pair_shift_words"]
    image_rows = [r for r in manifest if r["category"] == "image_output_step2"]
    if len({r["entropy_input_sha256"] for r in drbg_rows}) != N_STREAMS or len({r["nonce_sha256"] for r in drbg_rows}) != N_STREAMS:
        raise AssertionError("HMAC-DRBG seed and nonce fixtures are not unique")
    if len({r["user_key_sha256"] for r in pair_rows}) != N_STREAMS or len({r["image_id_sha256"] for r in pair_rows}) != N_STREAMS:
        raise AssertionError("Pair-shift UserKey or ImageID fixtures are not unique")
    if len({r["user_key_sha256"] for r in image_rows}) != N_STREAMS or len({r["image_id_sha256"] for r in image_rows}) != N_STREAMS:
        raise AssertionError("Image-output UserKey or ImageID fixtures are not unique")
    r1_rows = [r for r in context_rows if r["category"] == "cryptographic_block_r1_values"]
    tag_rows = [r for r in context_rows if r["category"] == "authentication_tag_stream"]
    if len(r1_rows) != r1_contexts_per_stream * N_STREAMS or len({r["user_key_sha256"] for r in r1_rows}) != len(r1_rows):
        raise AssertionError("Block-r1 context keys are not unique")
    if len(tag_rows) != tag_contexts_per_stream * N_STREAMS or len({r["user_key_sha256"] for r in tag_rows}) != len(tag_rows) or len({r["image_id_sha256"] for r in tag_rows}) != len(tag_rows):
        raise AssertionError("Authentication-tag context keys or ImageIDs are not unique")
    for category in CATEGORIES:
        path = raw_root / category / "input.bin"
        if path.stat().st_size != N_STREAMS * STREAM_BYTES:
            raise AssertionError(f"NIST input size incorrect for {category}")
    return manifest, context_rows, recovery_rows


def parse_native_report(path: Path) -> dict[str, list[dict[str, str]]]:
    found: dict[str, list[dict[str, str]]] = {t: [] for t in TEST_NAMES}
    for line in path.read_text(errors="replace").splitlines():
        match = REPORT_LINE.match(line)
        if match:
            test = match.group("test")
            if test not in found:
                raise AssertionError(f"Unexpected STS report test row: {test}")
            found[test].append({
                "uniformity_p_value": match.group("uniformity"),
                "pass_proportion": match.group("proportion"),
            })
    for test, count in COMPONENT_COUNTS.items():
        if len(found[test]) != count:
            raise AssertionError(f"{path}: expected {count} summary rows for {test}, got {len(found[test])}")
    return found


def stats_statuses(test: str, stats_path: Path) -> list[str | None]:
    text = stats_path.read_text(errors="replace")
    ncomp = COMPONENT_COUNTS[test]
    if test == "LinearComplexity":
        # STS 2.1.2 writes first-level p-values but omits per-sequence
        # SUCCESS/FAILURE labels for this test. Apply the unchanged alpha rule
        # to its native six-decimal results and validate aggregate counts
        # against finalAnalysisReport.txt below.
        vals = [v.strip() for v in stats_path.with_name("results.txt").read_text(errors="replace").splitlines() if v.strip()]
        if len(vals) != N_STREAMS:
            raise AssertionError(f"LinearComplexity: expected {N_STREAMS} native p-values, got {len(vals)}")
        return ["pass" if float(v) >= ALPHA else "fail" for v in vals]
    if test == "Runs":
        blocks = re.split(r"RUNS TEST", text, flags=re.IGNORECASE)[1:]
        if len(blocks) != N_STREAMS:
            raise AssertionError(f"Runs: expected {N_STREAMS} stream sections, got {len(blocks)}")
        statuses = []
        for block in blocks:
            if "PI ESTIMATOR CRITERIA NOT MET" in block:
                statuses.append("fail")
            else:
                mark = re.search(r"\b(SUCCESS|FAILURE)\b\s+p_value", block)
                if not mark:
                    raise AssertionError("Runs: missing native status for an applicable stream")
                statuses.append("pass" if mark.group(1) == "SUCCESS" else "fail")
        return statuses
    if test in ("RandomExcursions", "RandomExcursionsVariant"):
        heading = "RANDOM EXCURSIONS VARIANT TEST" if test == "RandomExcursionsVariant" else "RANDOM EXCURSIONS TEST"
        blocks = re.split(heading, text, flags=re.IGNORECASE)[1:]
        if len(blocks) != N_STREAMS:
            raise AssertionError(f"{test}: expected {N_STREAMS} stream sections, got {len(blocks)}")
        output: list[str | None] = []
        for block in blocks:
            if "TEST NOT APPLICABLE" in block:
                output.extend([None] * ncomp)
                continue
            marks = re.findall(r"\b(SUCCESS|FAILURE)\b", block)
            if len(marks) != ncomp:
                raise AssertionError(f"{test}: expected {ncomp} component statuses, got {len(marks)}")
            output.extend("pass" if value == "SUCCESS" else "fail" for value in marks)
        return output
    marks = re.findall(r"\b(SUCCESS|FAILURE)\b", text)
    expected = N_STREAMS * ncomp
    if len(marks) != expected:
        raise AssertionError(f"{test}: expected {expected} statuses, got {len(marks)}")
    return ["pass" if value == "SUCCESS" else "fail" for value in marks]


def component_labels(test: str, sts_root: Path) -> list[str]:
    if test == "CumulativeSums":
        return ["forward", "reverse"]
    if test == "Serial":
        return ["p_value1 (delta_1)", "p_value2 (delta_2)"]
    if test == "RandomExcursions":
        return [f"state={x}" for x in (-4, -3, -2, -1, 1, 2, 3, 4)]
    if test == "RandomExcursionsVariant":
        return [f"state={x}" for x in (*range(-9, 0), *range(1, 10))]
    if test == "NonOverlappingTemplate":
        path = sts_root / "templates" / "template9"
        templates = [line.strip() for line in path.read_text().splitlines() if line.strip()]
        if len(templates) != 148:
            raise AssertionError(f"Expected 148 m=9 templates, got {len(templates)}")
        return [f"m=9 template={value}" for value in templates]
    if COMPONENT_COUNTS[test] == 1:
        return ["single"]
    return [f"component={i + 1}" for i in range(COMPONENT_COUNTS[test])]


def run_sts(sts_source: Path, manifest: list[dict]) -> tuple[dict[str, Path], dict[str, Path], list[dict]]:
    raw_reports_root = OUT / "raw_reports"
    raw_reports_root.mkdir(parents=True, exist_ok=True)
    final_reports: dict[str, Path] = {}
    input_paths: dict[str, Path] = {}
    summary_rows: list[dict] = []
    runtime = Path(tempfile.mkdtemp(prefix=".sts_2_1_2_runtime_", dir=OUT))
    sts_root = runtime / "sts"
    shutil.copytree(sts_source, sts_root)
    try:
        for category in CATEGORIES:
            print(f"running official STS 2.1.2: {category}", flush=True)
            exp = sts_root / "experiments" / "AlgorithmTesting"
            shutil.rmtree(exp, ignore_errors=True)
            for test in TEST_NAMES:
                (exp / test).mkdir(parents=True, exist_ok=True)
            input_path = (OUT / "raw_streams" / category / "input.bin").resolve()
            input_paths[category] = input_path
            cached_dir = OUT / "raw_reports" / category
            cached_report = OUT / f"{category}_finalAnalysisReport.txt"
            if not ((cached_dir / "freq.txt").is_file() and (cached_dir / "finalAnalysisReport.txt").is_file() and cached_report.is_file()):
                if category == "image_output_step2":
                    cached_dir = OUT / "step2_image_derived_keyed_intermediate_raw_reports"
                    cached_report = OUT / "step2_image_derived_keyed_intermediate_finalAnalysisReport.txt"
                elif category == "image_output_final_marked":
                    cached_dir = OUT / "final_marked_rgb_raw_reports"
                    cached_report = OUT / "final_marked_rgb_finalAnalysisReport.txt"
            reusable = (cached_dir / "freq.txt").is_file() and (cached_dir / "finalAnalysisReport.txt").is_file() and cached_report.is_file()
            if reusable:
                if cached_dir.resolve() != (raw_reports_root / category).resolve():
                    shutil.rmtree(raw_reports_root / category, ignore_errors=True)
                    shutil.copytree(cached_dir, raw_reports_root / category)
                nist_report = raw_reports_root / category / "finalAnalysisReport.txt"
                final = OUT / f"{category}_finalAnalysisReport.txt"
                if cached_report.resolve() != final.resolve():
                    shutil.copyfile(cached_report, final)
                final_reports[category] = final
                raw_copy = raw_reports_root / category
                print(f"reusing preserved official STS output for {category}", flush=True)
            else:
                answers = f"0\n{input_path}\n1\n0\n{N_STREAMS}\n1\n"
                proc = subprocess.run(
                    [str(sts_root / "assess"), str(STREAM_BITS)], cwd=sts_root,
                    input=answers, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, timeout=6 * 60 * 60,
                )
                if "Statistical Testing Complete" not in proc.stdout:
                    raise RuntimeError(f"STS failed for {category}:\n{proc.stdout[-3000:]}")
                nist_report = exp / "finalAnalysisReport.txt"
                raw_copy = raw_reports_root / category
                shutil.copytree(exp, raw_copy)
                final = OUT / f"{category}_finalAnalysisReport.txt"
                shutil.copyfile(nist_report, final)
                final_reports[category] = final
            freq = raw_copy / "freq.txt"
            freq_rows = re.findall(r"BITSREAD\s*=\s*(\d+)\s+0s\s*=\s*(\d+)\s+1s\s*=\s*(\d+)", freq.read_text(errors="replace"))
            if len(freq_rows) != N_STREAMS or any(int(r[0]) != STREAM_BITS for r in freq_rows):
                raise AssertionError(f"STS did not consume exactly {N_STREAMS} streams of {STREAM_BITS} bits")
            raw_input = input_path.read_bytes()
            for i, values in enumerate(freq_rows):
                chunk = raw_input[i * STREAM_BYTES:(i + 1) * STREAM_BYTES]
                expected_ones = sum(byte.bit_count() for byte in chunk)
                if int(values[2]) != expected_ones or int(values[1]) != STREAM_BITS - expected_ones:
                    raise AssertionError(f"STS binary bit counts disagree with raw stream {i + 1}")
            by_test = parse_native_report(nist_report)
            for test in TEST_NAMES:
                ncomp = COMPONENT_COUNTS[test]
                test_dir = raw_copy / test
                master_values = [v.strip() for v in (test_dir / "results.txt").read_text(errors="replace").splitlines() if v.strip()]
                if len(master_values) != N_STREAMS * ncomp:
                    raise AssertionError(f"{category}/{test}: raw NIST results have {len(master_values)} p-values")
                statuses = stats_statuses(test, test_dir / "stats.txt")
                labels = component_labels(test, sts_root)
                if len(labels) != ncomp:
                    raise AssertionError(f"{category}/{test}: component label count mismatch")
                # NIST writes the master results file stream-major. Verify the
                # official component partition files before indexing any rows.
                if ncomp > 1:
                    for comp in range(ncomp):
                        part = test_dir / f"data{comp + 1}.txt"
                        if not part.is_file():
                            raise AssertionError(f"Missing official component partition: {part}")
                        part_values = [v.strip() for v in part.read_text(errors="replace").splitlines() if v.strip()]
                        expected = [master_values[s * ncomp + comp] for s in range(N_STREAMS)]
                        if len(part_values) != N_STREAMS or [float(v) for v in part_values] != [float(v) for v in expected]:
                            raise AssertionError(f"NIST component partition disagrees for {category}/{test}/{comp + 1}")
                for comp in range(ncomp):
                    marks = [statuses[s * ncomp + comp] for s in range(N_STREAMS)]
                    pvals = [master_values[s * ncomp + comp] for s in range(N_STREAMS)]
                    valid = [s for s in marks if s is not None]
                    passes = sum(s == "pass" for s in valid)
                    fails = sum(s == "fail" for s in valid)
                    nas = N_STREAMS - len(valid)
                    row = by_test[test][comp]
                    reported = row["pass_proportion"]
                    if reported not in ("------", ""):
                        numerator, _denominator = reported.split("/", 1)
                        if passes != int(numerator):
                            raise AssertionError(
                                f"{category}/{test}/{labels[comp]}: per-stream pass count {passes} "
                                f"does not match native STS summary {reported}"
                            )
                    summary_rows.append({
                        "category": category,
                        "test_name": test,
                        "component": labels[comp],
                        "valid_streams": len(valid),
                        "pass_count": passes,
                        "fail_count": fails,
                        "not_applicable_count": nas,
                        "uniformity_p_value": row["uniformity_p_value"],
                        "pass_proportion": row["pass_proportion"],
                        "alpha": ALPHA,
                        "stream_length_bits": STREAM_BITS,
                        "nist_version": "2.1.2",
                    })
            freq_path = raw_copy / "freq.txt"
            input_hash = sha(input_path.read_bytes())
            expected_hashes = {r.get("category_input_sha256") for r in manifest if r["category"] == category}
            if expected_hashes != {input_hash}:
                raise AssertionError(f"Input file hash/manifest mismatch for {category}")
            print(f"completed {category}; freq rows={len(freq_rows)}; input sha256={input_hash}", flush=True)
    finally:
        shutil.rmtree(runtime, ignore_errors=True)
    return final_reports, input_paths, summary_rows


def write_results_and_summary(summary_rows: list[dict]) -> list[dict]:
    manifest_path = OUT / "stream_manifest.csv"
    with manifest_path.open(newline="", encoding="utf-8") as f:
        stream_rows = list(csv.DictReader(f))
    manifest_by_category = {
        c: [r for r in stream_rows if r["category"] == c] for c in CATEGORIES
    }
    result_rows: list[dict] = []
    summary_by = {(r["category"], r["test_name"], r["component"]): r for r in summary_rows}
    with tempfile.TemporaryDirectory(prefix="nist_result_lookup_") as td:
        # Raw STS output paths are stable and retained under raw_reports.
        for category in CATEGORIES:
            for test in TEST_NAMES:
                ncomp = COMPONENT_COUNTS[test]
                test_dir = OUT / "raw_reports" / category / test
                vals = [v.strip() for v in (test_dir / "results.txt").read_text(errors="replace").splitlines() if v.strip()]
                statuses = stats_statuses(test, test_dir / "stats.txt")
                labels = [r["component"] for r in summary_rows if r["category"] == category and r["test_name"] == test]
                if len(labels) != ncomp:
                    raise AssertionError(f"{category}/{test}: summary component labels missing")
                for stream_offset, stream in enumerate(manifest_by_category[category]):
                    si = int(stream["stream_index"])
                    for comp in range(ncomp):
                        component = labels[comp]
                        item = summary_by[(category, test, component)]
                        mark = statuses[stream_offset * ncomp + comp]
                        value = vals[stream_offset * ncomp + comp]
                        if mark is None:
                            value = ""
                        result_rows.append({
                            "category": category,
                            "image_or_source": stream["image_or_source"],
                            "stream_index": si,
                            "test_name": test,
                            "component": component,
                            "p_value": value,
                            "status": "not-applicable" if mark is None else mark,
                            "pass_proportion": item["pass_proportion"],
                            "uniformity_p_value": item["uniformity_p_value"],
                            "alpha": ALPHA,
                            "stream_length_bits": STREAM_BITS,
                            "nist_version": "2.1.2",
                            "p_value_source": f"raw_reports/{category}/{test}/results.txt",
                            "native_precision": "6 decimal places; 0.000000 is rounded output, not missing",
                            "raw_stream_sha256": stream["stream_sha256"],
                        })
    row_writer(OUT / "results.csv", result_rows)
    row_writer(OUT / "per_test_summary.csv", summary_rows)

    counts = {}
    for c in CATEGORIES:
        rows = [r for r in summary_rows if r["category"] == c]
        counts[c] = {
            s: sum(int(r[{"pass": "pass_count", "fail": "fail_count", "not-applicable": "not_applicable_count"}[s]]) for r in rows)
            for s in ("pass", "fail", "not-applicable")
        }
    lines = [
        "NIST SP 800-22 Rev. 1a evaluation; official NIST STS 2.1.2.",
        "All six categories use 100 streams of exactly 1,000,000 bits; alpha=0.01.",
        "The p-value column in results.csv contains each individual first-level p-value as printed by STS (six decimals).",
        "A printed 0.000000 is a rounded STS value, not a missing p-value. N/A means the NIST test was not applicable.",
        "Uniformity p-values are second-level NIST values from finalAnalysisReport.txt and are separate from first-level p-values.",
        "No overall NIST pass or cryptographic security claim is made.",
    ]
    for c in CATEGORIES:
        lines += ["", f"[{c}] outcome totals: {counts[c]}", "| Test | Component | Valid | Pass | Fail | N/A | Uniformity p-value | Pass proportion |", "|---|---|---:|---:|---:|---:|---:|---:|"]
        for r in [x for x in summary_rows if x["category"] == c]:
            lines.append(
                f"| {r['test_name']} | {r['component']} | {r['valid_streams']} | {r['pass_count']} | {r['fail_count']} | {r['not_applicable_count']} | {r['uniformity_p_value']} | {r['pass_proportion']} |"
            )
    lines += ["", "Detailed individual first-level p-values: results.csv", "Full official test-by-test output: raw_reports/<category>/AlgorithmTesting/", "Raw NIST input files: raw_streams/<category>/input.bin"]
    (OUT / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result_rows


def component_spec_text() -> list[str]:
    return [
        "cryptographic_hmac_drbg: 100 independent streams. Each uses a unique 32-byte deterministic test entropy input and 16-byte nonce, then the authenticated-TPE HMAC_DRBG(SHA-256) implementation with personalization 'group-perm'. Each stream concatenates 31,250 successive 4-byte Generate outputs (1,000,000 bits). This extends the same implementation beyond the 255 Fisher-Yates draws typically consumed per channel; no value is repeated or padded.",
        "cryptographic_pair_shift_words: 100 independent UserKey/ImageID fixtures. Each stream contains the first 31,250 distinct valid (channel, block_id, pair_index) HMAC inputs, ordered channel 0..2, block 0..255, pair 0..511. Each output is the exact first 32 digest bits used by pair_shift before the implementation's class-size modulo. This tests the raw HMAC-derived word, not a fabricated image and not post-modulo shift values.",
        "cryptographic_block_r1_values: Each 1,000,000-bit sequence is the exact two-bit block_r1 output across independent UserKey contexts in context/channel/block order. A single context yields only 768 values, so 652 independent key contexts are used per NIST stream; the last context contributes only the 32 values needed for the exact prefix. Each r1 is encoded as two MSB-first bits. Keys are not reused and no values are repeated or padded.",
        "Authentication-tag stream: 100 separate NIST bitstreams are assembled from raw 256-bit HMAC-SHA256 group tags generated by the implementation _group_mac. Each stream uses 21 independent UserKey/ImageID contexts; all 2,100 pairs are unique. Six fixed Step-1 public UCT reference images supply authenticated group data round-robin. Tags are concatenated in context/channel/group order (4,032 tags generated per sequence) and truncated at exactly 1,000,000 bits, within the final tag bytes. This is an isolated tag-component diagnostic, not 100 full image-protection runs.",
        "image_output_step2: the first 1,000,000 bits of row-major C-order RGB uint8 bytes from the Step-2 image-derived keyed intermediate, before authentication-tag embedding.",
        "image_output_final_marked: the first 1,000,000 bits of row-major C-order RGB uint8 bytes from the final RCM-marked authenticated image.",
    ]


def write_provenance(sts_source: Path, manifest: list[dict], input_paths: dict[str, Path], runner_hash: str) -> list[dict]:
    records = []
    for p in sorted(sts_source.rglob("*")):
        if p.is_file():
            records.append({"relative_path": p.relative_to(sts_source).as_posix(), "size_bytes": p.stat().st_size, "sha256": sha(p.read_bytes())})
    row_writer(OUT / "nist_sts_source_manifest.csv", records)
    tree = "\n".join(f"{r['sha256']}  {r['relative_path']}" for r in records).encode("utf-8")
    nist_binary = sts_source / "assess"
    input_hashes = {c: sha(p.read_bytes()) for c, p in input_paths.items()}
    by_category = {c: [r for r in manifest if r["category"] == c] for c in CATEGORIES}
    old_commit = subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip()
    py_version = sys.version.replace("\n", " ")
    prov = [
        "Evaluation: authenticated-TPE-only NIST SP 800-22 Rev. 1a statistical diagnostics.",
        "NIST STS version: 2.1.2, downloaded from the NIST CSRC SP 800-22 Documentation and Software page.",
        f"NIST assess executable SHA-256: {sha(nist_binary.read_bytes())}",
        f"NIST STS extracted tree SHA-256: {sha(tree)} (see nist_sts_source_manifest.csv)",
        f"Runner SHA-256: {runner_hash}",
        f"Authenticated-TPE implementation SHA-256: {sha((PROJECT / 'src' / 'authenticated_tpe.py').read_bytes())}",
        f"Authenticated-TPE source baseline commit: {old_commit}",
        f"Python: {py_version}",
        f"NumPy: {np.__version__}",
        f"Pillow: {pillow_version}",
        f"Platform: {platform.platform()}",
        f"Command: {sys.executable} authenticated_tpe/experiments/run_nist_sp800_22_comprehensive.py --sts-dir <official sts-2.1.2 extraction> --streams 100 --bits 1000000 --alpha 0.01",
        "STS interaction: generator choice 0 (input file); all 15 tests; default parameters; 100 bitstreams; binary input mode 1.",
        "NIST defaults: block-frequency M=128; non-overlapping template m=9 (148 templates); overlapping template m=9; approximate entropy m=10; serial m=16; linear complexity M=500.",
        "STS input serialization: packed binary bytes; each byte consumed most-significant bit first; one 125,000-byte chunk per 1,000,000-bit stream.",
        "Alpha=0.01 is the NIST STS default compiled threshold; unchanged.",
        "The STS native results.txt and stats.txt print individual p-values to six decimal places. 0.000000 is retained as native rounded output; it is not replaced with zero precision or called missing.",
        "Uniformity p-values and pass proportions are the separate second-level results reported by STS finalAnalysisReport.txt.",
        "Key and ImageID bytes are deterministic public test fixtures. Only SHA-256 digests are recorded; no production secret is used or emitted.",
        "The six source images are public UCT airplane, baboon, couple, girl, lena, peppers. Source image hashes and all stream hashes are in stream_manifest.csv.",
        "Authentication-tag stream key/ImageID provenance: 2,100 independent fixture pairs, with each 1,000,000-bit sequence taking raw HMAC group tags from 21 contexts; see component_contexts.csv.",
    ]
    prov.extend(f"{c} input sha256: {input_hashes[c]}" for c in CATEGORIES)
    (OUT / "provenance.txt").write_text("\n".join(prov) + "\n", encoding="utf-8")
    return records


def write_report(summary_rows: list[dict], result_rows: list[dict], image_recovery: list[dict], sts_records: list[dict]) -> None:
    report = OUT / "NIST_AUTHENTICATED_TPE_REPORT.md"
    counts = {}
    for c in CATEGORIES:
        rows = [r for r in summary_rows if r["category"] == c]
        counts[c] = {s: sum(int(r[k]) for r in rows) for s, k in (("pass", "pass_count"), ("fail", "fail_count"), ("not-applicable", "not_applicable_count"))}
    lines = [
        "# NIST SP 800-22 Rev. 1a Evaluation of the Authenticated-TPE Method",
        "",
        "## Scope and interpretation",
        "",
        "This report presents separate statistical diagnostics for authenticated-TPE cryptographic components and for the image outputs. NIST SP 800-22 is a statistical test suite, not a security proof. A test outcome does not establish security or insecurity by itself.",
        "",
        "## Method and implementation configuration",
        "",
        "The implementation processes 512×512 RGB uint8 arrays in non-overlapping 32×32 blocks. It uses 256 blocks per channel, 512 adjacent pixel pairs per block, groups four ordered blocks, 64 groups per channel and 192 groups per RGB image. Authentication uses HMAC-SHA256; grouping uses the implemented HMAC-DRBG; transforms are Step 1 pair-sum-preserving mapping, Step 2 image-derived keyed smaller-pixel re-encryption, and reversible contrast mapping (RCM) for tag embedding. Verification and exact recovery occur before plaintext release.",
        "",
        "The cryptographic-component categories test outputs used by the implementation. The Authentication-tag stream is raw 256-bit HMAC output, tested separately using independently generated keys and ImageIDs. The image-output categories are explicitly diagnostic and preserve the method's image-dependent structure.",
        "",
        "## NIST software and settings",
        "",
        "- Software: official NIST Statistical Test Suite 2.1.2, selected from the [NIST SP 800-22 documentation and software page](https://csrc.nist.gov/Projects/random-bit-generation/Documentation-and-Software).",
        "- Tests: all 15 STS tests; alpha = 0.01; default parameters (block frequency 128, non-overlapping templates m=9, overlapping template m=9, approximate entropy m=10, serial m=16, linear complexity M=500).",
        "- Sample: 100 streams for each category; each stream is exactly 1,000,000 bits; 600 streams total across six categories.",
        "- Input: NIST binary mode. The runner confirmed 100 `BITSREAD = 1000000` records per category. Each 125,000-byte stream is consumed MSB-first, matching the NIST `convertToBits` implementation.",
        "- NIST's native individual p-value output is six decimal places. The CSV preserves that output; a displayed `0.000000` is rounded output, not a missing p-value. No synthetic precision is added.",
        "- Deterministic component fixture bytes use SHA-256(domain_label || 0x00 || uint64_be(index)), truncated only where a 16-byte ImageID is needed. The exact domain labels, per-stream key/nonce digests, and fixture indexes are recorded in stream_manifest.csv and component_contexts.csv.",
        "",
        "## Exact stream-generation procedure",
        "",
    ]
    lines.extend(f"- {item}" for item in component_spec_text())
    lines += [
        "",
        "### Image and key fixture selection",
        "",
        "The image diagnostic uses the six available public UCT images in round-robin order: airplane, baboon, couple, girl, lena, peppers. Images are converted to RGB and resized to 512×512 only when required, using Pillow's default resize behavior to match the existing runner. For stream i, UserKey is SHA-256(`auth-tpe-nist-key-v1 || 00 || uint32_be(i)`) and ImageID is the first 16 bytes of SHA-256(`auth-tpe-nist-image-id-v1 || 00 || uint32_be(i)`). The paired Step-2 and marked outputs for one stream use the same test credentials. These are reproducibility fixtures, not production secrets. The exact eight CelebA-HQ source files were unavailable; no CelebA-HQ data is claimed or fabricated.",
        "The four cryptographic-component fixture families use domain-separated deterministic public bytes: HMAC-DRBG entropy/nonce, pair-shift key/ImageID, block-r1 keys, and authentication-tag key/ImageID. The tag category uses 2,100 unique UserKey/ImageID pairs across the 100 streams. These fixtures support repeatability and are public; they do not test entropy sources or secret-key security.",
        "",
        "### Byte-to-bit serialization",
        "",
        "Cryptographic byte outputs are recorded in generation order. For the image categories, the tested object is row-major C-order RGB uint8 bytes. The first 125,000 bytes are the exact 1,000,000-bit prefix. All inputs are passed as packed binary; NIST reads every byte from its most significant bit to its least significant bit. No LSB-first or full-image variant was run, and no image-output padding was used.",
        "",
        "## Results overview",
        "",
        "### Cryptographic-component evaluation",
        "",
        "| Category | Pass | Fail | N/A |",
        "|---|---:|---:|---:|",
    ]
    for c in CATEGORIES[:4]:
        lines.append(f"| {'Authentication-tag stream' if c == 'authentication_tag_stream' else c} | {counts[c]['pass']} | {counts[c]['fail']} | {counts[c]['not-applicable']} |")
    lines += [
        "",
        "### Image-output statistical diagnostic",
        "",
        "| Category | Pass | Fail | N/A | Exact recovery |",
        "|---|---:|---:|---:|---:|",
    ]
    exact_n = sum(r["exact_recovery"] == "True" or r["exact_recovery"] is True for r in image_recovery)
    for c in CATEGORIES[4:]:
        lines.append(f"| {c} | {counts[c]['pass']} | {counts[c]['fail']} | {counts[c]['not-applicable']} | {exact_n}/100 |")
    lines += [
        "",
        "The image outputs retain source-image and RCM/tag structure by design. Their image-output tests are diagnostics and should not be expected to behave like an ideal random-number stream. Low p-values in those categories do not by themselves establish a cryptographic implementation defect. The cryptographic component results assess pseudorandom outputs separately, but they also do not constitute a security proof.",
        "",
        "## Full test/component tables",
        "",
        "The tables below give, for every NIST test/component, the number of valid streams, first-level pass/fail/N/A counts, native NIST uniformity p-value, and pass proportion. The uniformity p-value is a second-level value over first-level p-values and is not an individual stream p-value.",
    ]
    for c in CATEGORIES:
        lines += ["", f"### {'Authentication-tag stream' if c == 'authentication_tag_stream' else c}", "", "| NIST test | Component | Valid | Pass | Fail | N/A | Uniformity p-value | Pass proportion |", "|---|---|---:|---:|---:|---:|---:|---:|"]
        for r in (x for x in summary_rows if x["category"] == c):
            lines.append(f"| {r['test_name']} | {r['component']} | {r['valid_streams']} | {r['pass_count']} | {r['fail_count']} | {r['not_applicable_count']} | {r['uniformity_p_value']} | {r['pass_proportion']} |")
    lines += [
        "",
        "## Individual p-values and official reports",
        "",
        "- [`results.csv`](results.csv) contains one row for every stream and component with the individual first-level p-value, status, pass proportion, uniformity p-value, alpha, bit length, NIST version, and raw input stream hash. N/A p-values are blank and explicitly labeled not applicable.",
        "- [`per_test_summary.csv`](per_test_summary.csv) contains the complete per-test/component summary.",
        "- [`raw_reports/`](raw_reports/) preserves complete STS `finalAnalysisReport.txt`, per-test `stats.txt`, master `results.txt`, and official component partition files for all six categories.",
        "- The three professor-requested report aliases are [`cryptographic_components_finalAnalysisReport.txt`](cryptographic_components_finalAnalysisReport.txt), [`image_output_step2_finalAnalysisReport.txt`](image_output_step2_finalAnalysisReport.txt), and [`image_output_final_marked_finalAnalysisReport.txt`](image_output_final_marked_finalAnalysisReport.txt).",
        "- [`raw_streams/`](raw_streams/) contains the exact packed binary NIST inputs. `stream_manifest.csv` records each stream's byte offset, size, hash, key/ImageID digests and source details.",
        "",
        "## Provenance and reproducibility",
        "",
        "See [`provenance.txt`](provenance.txt), [`stream_manifest.csv`](stream_manifest.csv), [`component_contexts.csv`](component_contexts.csv), and [`nist_sts_source_manifest.csv`](nist_sts_source_manifest.csv). They record source and executable hashes, runtime versions, platform, exact command and settings, input image hashes, per-stream hashes, and digest-only test credential identifiers. No test key or ImageID bytes are written.",
        "",
        "## Limitations",
        "",
        "- NIST SP 800-22 is not a security proof and does not replace cryptanalysis.",
        "- Image-output streams preserve image-related information by design; NIST results on those streams are diagnostics, not proof of security or insecurity.",
        "- NPCR/UACI and NIST outcomes do not prove cryptographic security.",
        "- The evaluation uses six public UCT images because the eight CelebA-HQ source files were unavailable. Authenticated-TPE is implemented with a fixed 32×32 block size; authenticated 8×8 and 16×16 results are therefore not reported.",
        "- The component fixtures are deterministic and public for reproducibility. NIST testing does not assess entropy quality, key secrecy, unpredictability, formal security, or independent cryptanalysis.",
        "",
        "## References",
        "",
        "1. NIST, [SP 800-22 Rev. 1a](https://doi.org/10.6028/NIST.SP.800-22r1a). NIST notes statistical testing cannot substitute for cryptanalysis.",
        "2. NIST, [SP 800-22 documentation and software](https://csrc.nist.gov/Projects/random-bit-generation/Documentation-and-Software), including the NIST STS download and software revision history.",
        "",
    ]
    report.write_text("\n".join(lines), encoding="utf-8")
    (OUT / "README.md").write_text(
        "# Authenticated-TPE NIST output\n\n"
        "This directory contains separate NIST SP 800-22 evaluation of actual authenticated-TPE cryptographic components and image-output statistical diagnostics. Read [`NIST_AUTHENTICATED_TPE_REPORT.md`](NIST_AUTHENTICATED_TPE_REPORT.md) or its [`PDF companion`](NIST_AUTHENTICATED_TPE_REPORT.pdf) first. The raw 256-bit HMAC output is tested as the separate Authentication-tag stream category using unique key/ImageID fixtures.\n\n"
        "Individual first-level p-values are in [`results.csv`](results.csv); second-level NIST uniformity p-values and pass proportions are in that CSV and [`per_test_summary.csv`](per_test_summary.csv). Native STS p-values are printed to six decimal places. `0.000000` is retained as rounded output and is not missing. `raw_streams/` holds the exact packed binary inputs; `raw_reports/` holds complete official NIST reports and raw test output.\n\n"
        "No overall NIST pass or security proof is claimed. The image output is expected to retain image structure. All image data is from six available UCT images; no CelebA-HQ images are claimed.\n",
        encoding="utf-8",
    )


def run(args: argparse.Namespace) -> None:
    sts_source = args.sts_dir.resolve()
    if not (sts_source / "assess").is_file() or not (sts_source / "templates" / "template9").is_file():
        raise FileNotFoundError("Provide the extracted official NIST STS 2.1.2 directory (assess and templates/template9 required)")
    if args.streams != N_STREAMS or args.bits != STREAM_BITS or args.alpha != ALPHA:
        raise ValueError("This reproducible protocol is fixed at 100 streams, 1,000,000 bits, alpha=0.01")
    OUT.mkdir(parents=True, exist_ok=True)
    print("Loading validated generated streams or generating deterministic test fixtures.", flush=True)
    manifest_path = OUT / "stream_manifest.csv"
    generated_ready = manifest_path.is_file() and all(
        (OUT / "raw_streams" / c / "input.bin").is_file()
        and (OUT / "raw_streams" / c / "input.bin").stat().st_size == N_STREAMS * STREAM_BYTES
        for c in CATEGORIES
    )
    if generated_ready:
        with manifest_path.open(newline="", encoding="utf-8") as f:
            manifest = list(csv.DictReader(f))
        generated_ready = len(manifest) == len(CATEGORIES) * N_STREAMS and {r["category"] for r in manifest} == set(CATEGORIES)
    if generated_ready:
        def read_csv_rows(filename: str) -> list[dict]:
            path = OUT / filename
            with path.open(newline="", encoding="utf-8") as f:
                return list(csv.DictReader(f))
        contexts = read_csv_rows("component_contexts.csv")
        recoveries = read_csv_rows("image_recovery.csv")
        for row in manifest:
            row["stream_index"] = int(row["stream_index"])
            row["stream_length_bits"] = int(row["stream_length_bits"])
            row["byte_offset"] = int(row["byte_offset"])
            row["stream_bytes"] = int(row["stream_bytes"])
        print("Reusing complete six-category raw inputs and manifests.", flush=True)
    else:
        manifest, contexts, recoveries = generate_streams()
    for category in CATEGORIES:
        rows = [r for r in manifest if r["category"] == category]
        input_path = OUT / "raw_streams" / category / "input.bin"
        input_hash = sha(input_path.read_bytes())
        for row in rows:
            row["category_input_sha256"] = input_hash
    row_writer(OUT / "stream_manifest.csv", manifest)
    row_writer(OUT / "component_contexts.csv", contexts)
    row_writer(OUT / "image_recovery.csv", recoveries)
    final_reports, input_paths, summaries = run_sts(sts_source, manifest)
    # Keep the complete native tree for each category; also provide requested
    # concise aliases without altering the official reports.
    crypto_alias = OUT / "cryptographic_components_finalAnalysisReport.txt"
    with crypto_alias.open("w", encoding="utf-8") as f:
        for category in CATEGORIES[:4]:
            f.write(f"\n===== {category} =====\n")
            f.write(final_reports[category].read_text(errors="replace"))
    # Backward-compatible names used by the previous authenticated-TPE report.
    shutil.copyfile(final_reports["image_output_step2"], OUT / "step2_image_derived_keyed_intermediate_finalAnalysisReport.txt")
    shutil.copyfile(final_reports["image_output_final_marked"], OUT / "final_marked_rgb_finalAnalysisReport.txt")
    for c, old_name in (("image_output_step2", "step2_image_derived_keyed_intermediate"), ("image_output_final_marked", "final_marked_rgb")):
        src = OUT / "raw_reports" / c
        dst = OUT / f"{old_name}_raw_reports"
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(src, dst)
    result_rows = write_results_and_summary(summaries)
    runner_hash = sha(Path(__file__).read_bytes())
    sts_records = write_provenance(sts_source, manifest, input_paths, runner_hash)
    write_report(summaries, result_rows, recoveries, sts_records)
    print(f"completed; streams={len(manifest)} result_rows={len(result_rows)} summary_components={len(summaries)}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sts-dir", type=Path, required=True)
    ap.add_argument("--streams", type=int, default=N_STREAMS)
    ap.add_argument("--bits", type=int, default=STREAM_BITS)
    ap.add_argument("--alpha", type=float, default=ALPHA)
    run(ap.parse_args())


if __name__ == "__main__":
    main()
