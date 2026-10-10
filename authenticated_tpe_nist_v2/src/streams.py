"""Predefined, non-repeating stream families for the corrected NIST protocol.

Design rules (see docs/STREAM_DEFINITIONS.md):

*   100 streams per category, 1,000,000 bits (125,000 bytes) per stream.
*   Every stream is *predefined* and deterministic: it is a pure function of the
    published constants in this file, so a third party can regenerate it and
    check the SHA-256 values recorded in ``output/stream_manifest.csv``.
*   No stream, UserKey, ImageID, image or counter combination is reused: key and
    ImageID indices are partitioned across categories and streams, no image
    repeats inside a stream, and the generated streams are verified to be
    pairwise distinct.
*   Stream length is never obtained by repeating a shorter stream.
"""
from __future__ import annotations

import hashlib
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from PIL import Image

_HERE = Path(__file__).resolve()
SRC = _HERE.parent
ROOT = SRC.parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import atpe_v2 as v2  # noqa: E402

STREAM_BITS = 1_000_000
STREAM_BYTES = STREAM_BITS // 8
STREAM_COUNT = 100
ALPHA = 0.01
IMAGE_SIZE = 512
UCT_SOURCE = ROOT.parent / "tpe_rdh_reproduction" / "input" / "uct_colour"
UCT_NAMES = ("airplane", "baboon", "couple", "girl", "lena", "peppers")
UCID_RAW_DIR_DEFAULT = Path("/home/ubuntu/work/ucid")
IMAGE_CACHE = ROOT / "input" / "images_512"
UCID_SOURCE_NOTE = ("github.com/girfa/ColorImageDatasets, UCID-1338/1.tif..100.tif "
                    "(retrieved 2026-10-11)")

# Disjoint UserKey / ImageID index partitions, one index per instance.
KEY_RANGES = {
    "pair_shift": (1, 100),
    "block_r1": (101, 700),
    "auth_tag": (701, 2800),
    "reduced_shift_diag": (2801, 2900),
    "ciphertext_diag": (2901, 3000),
    "recovered_diag": (3001, 3100),
}
DRBG_INSTANCES = (1, STREAM_COUNT)
TAG_INSTANCES_PER_STREAM = 21
R1_KEYS_PER_STREAM = 6
# The 100 diagnostic images are pool orders 0..99: the six UCT colour images the
# original report evaluated plus 94 distinct UCID photographs.  Every diagnostic
# stream therefore uses its own distinct image and no image is repeated.
DIAGNOSTIC_IMAGE_OFFSET = 0

CATEGORY_KIND = {
    "hmac_drbg": "cryptographic-component",
    "pair_shift": "cryptographic-component",
    "block_r1": "cryptographic-component",
    "auth_tag": "cryptographic-component",
    "reduced_shift_diag": "diagnostic",
    "ciphertext_diag": "diagnostic",
    "recovered_diag": "diagnostic",
}
CATEGORY_TITLE = {
    "hmac_drbg": "HMAC_DRBG (HMAC-SHA256) output",
    "pair_shift": "Step-1 pair-shift keystream (HMAC-SHA256 PRF digests)",
    "block_r1": "Step-2 block-r1 keystream (HMAC-SHA256 PRF digests)",
    "auth_tag": "HMAC-SHA256 authentication tags (192 per instance)",
    "reduced_shift_diag": "diagnostic: reduced pair-shift offsets packed as bytes",
    "ciphertext_diag": "diagnostic: actual encrypted (marked) images",
    "recovered_diag": "diagnostic: recovered/decrypted images (plaintext)",
}
CATEGORY_ORDER = list(CATEGORY_KIND)


def _u32(value: int) -> bytes:
    return int(value).to_bytes(4, "big")


def pool_key(index: int) -> bytes:
    return hashlib.sha256(b"atpe-v2|userkey|" + _u32(index)).digest()


def pool_image_id(index: int) -> bytes:
    return hashlib.sha256(b"atpe-v2|imageid|" + _u32(index)).digest()[:16]


def drbg_entropy(index: int) -> bytes:
    return hashlib.sha256(b"atpe-v2|drbg|entropy|" + _u32(index)).digest()


def drbg_nonce(index: int) -> bytes:
    return hashlib.sha256(b"atpe-v2|drbg|nonce|" + _u32(index)).digest()[:16]


# --------------------------------------------------------------------------
# Image pool
# --------------------------------------------------------------------------
def _sources(ucid_dir: Path) -> list[tuple[str, Path]]:
    items = [("uct", UCT_SOURCE / f"{name}.tif") for name in UCT_NAMES]
    items += [("ucid", ucid_dir / f"{i}.tif") for i in range(1, STREAM_COUNT + 1)]
    return items


def ensure_image_cache(ucid_dir: Path = UCID_RAW_DIR_DEFAULT) -> list[dict]:
    """Create the normalized 512x512 RGB cache once; return metadata only."""
    IMAGE_CACHE.mkdir(parents=True, exist_ok=True)
    meta = []
    for order, (family, path) in enumerate(_sources(ucid_dir)):
        if not path.is_file():
            raise FileNotFoundError(f"image source missing: {path}")
        cached = IMAGE_CACHE / f"{order:03d}_{family}_{path.stem}.png"
        if not cached.is_file():
            with Image.open(path) as handle:
                array = np.asarray(handle.convert("RGB").resize((IMAGE_SIZE, IMAGE_SIZE),
                                                                Image.LANCZOS), dtype=np.uint8)
            Image.fromarray(array, mode="RGB").save(cached, format="PNG", optimize=True)
        with Image.open(cached) as handle:
            array = np.asarray(handle.convert("RGB"), dtype=np.uint8)
        if array.shape != (IMAGE_SIZE, IMAGE_SIZE, 3):
            raise AssertionError(f"normalized image has wrong shape: {cached}")
        meta.append({"order": order, "family": family,
                     "source": str(path) if family == "uct" else f"{UCID_SOURCE_NOTE}::{path.name}",
                     "cache_file": str(cached.relative_to(ROOT)),
                     "pixel_sha256": hashlib.sha256(array.tobytes(order="C")).hexdigest(),
                     "cache_sha256": hashlib.sha256(cached.read_bytes()).hexdigest()})
    digests = [m["pixel_sha256"] for m in meta]
    if len(set(digests)) != len(digests):
        raise AssertionError("image pool contains duplicate images")
    return meta


_IMAGE_CACHE: dict[int, np.ndarray] = {}


def load_image(order: int) -> np.ndarray:
    """Lazy per-process loader (safe for worker processes)."""
    if order not in _IMAGE_CACHE:
        if not IMAGE_CACHE.is_dir():
            raise FileNotFoundError("image cache missing; run ensure_image_cache() first")
        matches = sorted(IMAGE_CACHE.glob(f"{order:03d}_*.png"))
        if not matches:
            raise FileNotFoundError(f"no cached image for order {order}")
        with Image.open(matches[0]) as handle:
            _IMAGE_CACHE[order] = np.ascontiguousarray(
                np.asarray(handle.convert("RGB"), dtype=np.uint8))
    return _IMAGE_CACHE[order]


def diagnostic_image_order(stream_index: int) -> int:
    """Stream i of an image diagnostic category uses its own distinct image."""
    return DIAGNOSTIC_IMAGE_OFFSET + (stream_index - 1) % STREAM_COUNT


def tag_instance_image_order(stream_index: int, instance: int) -> int:
    return ((stream_index - 1) * TAG_INSTANCES_PER_STREAM + instance) % (
        DIAGNOSTIC_IMAGE_OFFSET + STREAM_COUNT)


# --------------------------------------------------------------------------
# Stream builders
# --------------------------------------------------------------------------
@dataclass
class StreamRecord:
    category: str
    stream_index: int
    stream_bytes: bytes
    detail: dict = field(default_factory=dict)


def _drbg_stream(i: int) -> bytes:
    return v2.drbg_bytes(drbg_entropy(i), drbg_nonce(i), b"group-perm", STREAM_BYTES)


def _pair_shift_stream(i: int) -> bytes:
    index = KEY_RANGES["pair_shift"][0] + i - 1
    return v2.pair_shift_digests(pool_key(index), pool_image_id(index), STREAM_BYTES)


def _block_r1_stream(i: int) -> bytes:
    start = KEY_RANGES["block_r1"][0] + (i - 1) * R1_KEYS_PER_STREAM
    out = bytearray()
    for offset in range(R1_KEYS_PER_STREAM):
        out += v2.block_r1_digests(pool_key(start + offset))
        if len(out) >= STREAM_BYTES:
            break
    return bytes(out[:STREAM_BYTES])


def _reduced_shift_stream(i: int) -> bytes:
    index = KEY_RANGES["reduced_shift_diag"][0] + i - 1
    image = load_image(diagnostic_image_order(i))
    return v2.reduced_shift_bytes(image, pool_key(index), pool_image_id(index))[:STREAM_BYTES]


def _auth_tag_stream(i: int) -> tuple[bytes, list[int]]:
    start = KEY_RANGES["auth_tag"][0] + (i - 1) * TAG_INSTANCES_PER_STREAM
    out = bytearray()
    used: list[int] = []
    for instance in range(TAG_INSTANCES_PER_STREAM):
        order = tag_instance_image_order(i, instance)
        used.append(order)
        out += v2.group_tag_bytes_from_image(load_image(order), pool_key(start + instance),
                                            pool_image_id(start + instance))
        if len(out) >= STREAM_BYTES:
            break
    if len(set(used)) != len(used):
        raise AssertionError("an auth-tag stream reused an image inside the stream")
    return bytes(out[:STREAM_BYTES]), used


def _image_stream(i: int, recover: bool) -> tuple[bytes, dict]:
    category = "recovered_diag" if recover else "ciphertext_diag"
    index = KEY_RANGES[category][0] + i - 1
    image = load_image(diagnostic_image_order(i))
    key, image_id = pool_key(index), pool_image_id(index)
    protected = v2.protect_image(image, key, image_id)
    if recover:
        verified = v2.verify_and_decrypt(protected.marked_image, key, image_id)
        if not verified.accepted or not np.array_equal(verified.recovered_image, image):
            raise AssertionError(f"image stream {i}: authentication or recovery failed")
        payload = verified.recovered_image
        detail = {"mode": protected.mode, "exact_recovery": True, "accepted": True}
    else:
        payload = protected.marked_image
        detail = {"mode": protected.mode, "exact_recovery": None, "accepted": None}
    detail["image_order"] = diagnostic_image_order(i)
    detail["user_key_index"] = index
    detail["pairs_used"] = protected.pairs_used
    return np.ascontiguousarray(payload, dtype=np.uint8).tobytes(order="C")[:STREAM_BYTES], detail


def _work(task: tuple[str, int]) -> StreamRecord:
    category, i = task
    if category == "hmac_drbg":
        return StreamRecord(category, i, _drbg_stream(i),
                            {"instance": f"DRBG entropy index {i}",
                             "entropy_sha256": hashlib.sha256(drbg_entropy(i)).hexdigest(),
                             "nonce_sha256": hashlib.sha256(drbg_nonce(i)).hexdigest()})
    if category == "pair_shift":
        index = KEY_RANGES["pair_shift"][0] + i - 1
        return StreamRecord(category, i, _pair_shift_stream(i),
                            {"user_key_index": index,
                             "user_key_sha256": hashlib.sha256(pool_key(index)).hexdigest(),
                             "image_id_sha256": hashlib.sha256(pool_image_id(index)).hexdigest(),
                             "derivations": STREAM_BYTES // 32})
    if category == "block_r1":
        start = KEY_RANGES["block_r1"][0] + (i - 1) * R1_KEYS_PER_STREAM
        return StreamRecord(category, i, _block_r1_stream(i),
                            {"user_key_indices": f"{start}..{start + R1_KEYS_PER_STREAM - 1}",
                             "derivations": STREAM_BYTES // 32})
    if category == "reduced_shift_diag":
        index = KEY_RANGES["reduced_shift_diag"][0] + i - 1
        return StreamRecord(category, i, _reduced_shift_stream(i),
                            {"user_key_index": index,
                             "image_order": diagnostic_image_order(i)})
    if category == "auth_tag":
        data, used = _auth_tag_stream(i)
        start = KEY_RANGES["auth_tag"][0] + (i - 1) * TAG_INSTANCES_PER_STREAM
        return StreamRecord(category, i, data,
                            {"user_key_indices": f"{start}..{start + len(used) - 1}",
                             "image_orders": ";".join(str(u) for u in used),
                             "tags": 192 * len(used)})
    if category in ("ciphertext_diag", "recovered_diag"):
        data, detail = _image_stream(i, category == "recovered_diag")
        return StreamRecord(category, i, data, detail)
    raise ValueError(f"unknown category {category}")


def build_category(category: str, workers: int = 6) -> list[StreamRecord]:
    tasks = [(category, i) for i in range(1, STREAM_COUNT + 1)]
    if workers <= 1:
        return [_work(task) for task in tasks]
    with ProcessPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(_work, tasks))


def stream_ascii(data: bytes) -> str:
    """MSB-first ASCII expansion, as consumed by NIST STS input mode 0."""
    return "".join(f"{byte:08b}" for byte in data[:STREAM_BYTES])


def write_category(records: list[StreamRecord], out_dir: Path) -> list[dict]:
    bin_dir = out_dir / "streams"
    bin_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for record in records:
        payload = record.stream_bytes[:STREAM_BYTES]
        if len(payload) != STREAM_BYTES:
            raise AssertionError("stream shorter than 125,000 bytes")
        path = bin_dir / f"{record.category}_{record.stream_index:03d}.bin"
        path.write_bytes(payload)
        row = {
            "category": record.category,
            "kind": CATEGORY_KIND[record.category],
            "stream_index": record.stream_index,
            "stream_bits": STREAM_BITS,
            "stream_bytes": STREAM_BYTES,
            "binary_sha256": hashlib.sha256(payload).hexdigest(),
            "ascii_sha256": hashlib.sha256(stream_ascii(payload).encode("ascii")).hexdigest(),
            "stream_file": str(path.relative_to(ROOT)),
        }
        row.update({k: "" if v is None else v for k, v in record.detail.items()})
        rows.append(row)
    return rows


def check_no_repeats(rows: list[dict]) -> dict:
    per_category: dict[str, set[str]] = {}
    for row in rows:
        per_category.setdefault(row["category"], set()).add(row["binary_sha256"])
    report = {
        "total_streams": len(rows),
        "total_bits": len(rows) * STREAM_BITS,
        "unique_streams": len({row["binary_sha256"] for row in rows}),
        "unique_per_category": {k: len(v) for k, v in sorted(per_category.items())},
        "duplicate_stream_count": len(rows) - len({row["binary_sha256"] for row in rows}),
        "ascii_digests_match_streams": len({row["ascii_sha256"] for row in rows}) == len(rows),
    }
    report["all_categories_distinct"] = all(
        report["unique_per_category"].get(c) == STREAM_COUNT for c in CATEGORY_ORDER)
    report["ok"] = (report["duplicate_stream_count"] == 0
                    and report["all_categories_distinct"]
                    and report["ascii_digests_match_streams"])
    if not report["ok"]:
        raise AssertionError(f"stream independence check failed: {report}")
    return report


def check_image_reuse(rows: list[dict]) -> dict:
    """Verify no image repeats inside a stream and report cross-stream sharing."""
    inside_ok = True
    seen: dict[int, set[str]] = {}
    for row in rows:
        category = row.get("category")
        if category == "auth_tag":
            orders = [int(x) for x in str(row["image_orders"]).split(";") if x]
            if len(set(orders)) != len(orders):
                inside_ok = False
        elif category in ("ciphertext_diag", "recovered_diag", "reduced_shift_diag"):
            orders = [int(row["image_order"])]
        else:
            continue
        for order in orders:
            seen.setdefault(order, set()).add(f"{category}:{row['stream_index']}")
    return {"no_image_repeats_inside_a_stream": inside_ok,
            "distinct_images_referenced": len(seen),
            "sharing": {str(k): sorted(v) for k, v in sorted(seen.items())
                        if len(v) > 1}}


def key_partition_report() -> dict:
    used: dict[int, str] = {}
    for category, (start, end) in KEY_RANGES.items():
        for index in range(start, end + 1):
            if index in used:
                raise AssertionError(f"key index {index} shared by {used[index]} and {category}")
            used[index] = category
    return {"key_indices_used": len(used),
            "ranges": {k: list(v) for k, v in KEY_RANGES.items()},
            "drbg_instances": list(DRBG_INSTANCES),
            "disjoint": True}
