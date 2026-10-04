"""Shared, deterministic helpers for authenticated-TPE diagnostics."""
from __future__ import annotations

import hashlib

import numpy as np

IMAGE_ID_DOMAIN = b"authenticated-tpe-test-image-id-v1\x00"


def deterministic_test_image_id(label: str) -> bytes:
    """Derive a public 128-bit test fixture; never use this for production."""
    return hashlib.sha256(IMAGE_ID_DOMAIN + label.encode("ascii")).digest()[:16]


def flip_first_key_bit(key: bytes) -> bytes:
    """Match the original-project sweep: toggle the low bit of byte zero."""
    changed = bytearray(key)
    if not changed:
        raise ValueError("key must not be empty")
    changed[0] ^= 0x01
    return bytes(changed)


def make_differential_plaintext(image: np.ndarray, block_size: int = 32) -> np.ndarray:
    """Change each block's top-left R sample by +1, or -1 at 255."""
    if image.ndim != 3 or image.shape[2] != 3 or image.dtype != np.uint8:
        raise ValueError("image must be HxWx3 uint8 RGB")
    if block_size <= 0 or image.shape[0] % block_size or image.shape[1] % block_size:
        raise ValueError("image dimensions must be divisible by block_size")
    modified = image.copy()
    for row in range(0, image.shape[0], block_size):
        for col in range(0, image.shape[1], block_size):
            value = int(modified[row, col, 0])
            modified[row, col, 0] = value + 1 if value < 255 else value - 1
    return modified


def npcr_uaci(a: np.ndarray, b: np.ndarray) -> dict[str, tuple[float, float, int, int]]:
    """Return R/G/B and pooled RGB NPCR/UACI using the original formulas.

    NPCR is 100 * differing samples / sample count. UACI is 100 * the mean
    absolute uint8 difference / 255. Per-channel denominators are H*W; the
    pooled RGB denominator is H*W*3, matching the original key-sensitivity
    experiment's combined RGB calculation.
    """
    if a.shape != b.shape or a.ndim != 3 or a.shape[2] != 3:
        raise ValueError("inputs must be same-shaped HxWx3 arrays")
    aa = a.astype(np.int16)
    bb = b.astype(np.int16)
    diff = np.abs(aa - bb)
    changed = aa != bb
    h, w, channels = a.shape
    result = {}
    for i, name in enumerate(("R", "G", "B")):
        count = h * w
        n = int(changed[:, :, i].sum())
        result[name] = (n / count * 100.0,
                        float(diff[:, :, i].sum()) / (255.0 * count) * 100.0,
                        n, count)
    count = h * w * channels
    n = int(changed.sum())
    result["RGB"] = (n / count * 100.0,
                     float(diff.sum()) / (255.0 * count) * 100.0,
                     n, count)
    return result


def pack_msb_first(byte_values: np.ndarray, bit_count: int = 1_000_000) -> str:
    """Serialize uint8 C-order bytes MSB-first and truncate to bit_count."""
    raw = np.asarray(byte_values, dtype=np.uint8).tobytes(order="C")
    if len(raw) * 8 < bit_count:
        raise ValueError(f"need {bit_count} bits, got {len(raw) * 8}")
    return "".join(f"{value:08b}" for value in raw)[:bit_count]
