"""Measure one-bit key-sensitivity NPCR/UACI on UCT colour images.

This experiment keeps the plaintext image, payload, block size, and all other
pipeline parameters fixed. It encrypts once with the base 256-bit key and once
with a one-bit-flipped key, then compares the two ciphertext images using the
paper's NPCR/UACI normalization.

The result is a key-sensitivity check. It is intentionally separate from the
paper's Section 6.8 plaintext-differential NPCR/UACI experiment.
"""

from __future__ import annotations

import csv
from dataclasses import replace
from pathlib import Path
import sys

import cv2
import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from pipeline import DEFAULT_DEMO_KEY, DemoPipelineParameters, encrypt_rgb_image
from rdh import bits_from_bytes


FILENAMES = [
    "airplane.tif",
    "baboon.tif",
    "couple.tif",
    "girl.tif",
    "lena.tif",
    "peppers.tif",
]
BLOCK_SIZES = [8, 16, 32, 64]
PAYLOAD_BITS = bits_from_bytes(b"airplane key-sensitivity audit")


def load_rgb(path: Path) -> np.ndarray:
    """Load a source TIF as uint8 RGB."""

    image = cv2.imread(str(path), cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError(f"could not read image: {path}")
    return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)


def flip_first_key_bit(key: bytes) -> bytes:
    """Return a copy of a key with exactly one bit changed."""

    flipped = bytearray(key)
    flipped[0] ^= 0x01
    return bytes(flipped)


def npcr_uaci(cipher_a: np.ndarray, cipher_b: np.ndarray) -> dict[str, float]:
    """Compute per-channel and RGB-aggregate NPCR/UACI percentages."""

    if cipher_a.shape != cipher_b.shape:
        raise ValueError("ciphertext shapes differ")

    diff = cipher_a.astype(np.int16) - cipher_b.astype(np.int16)
    changed = cipher_a != cipher_b
    height, width, channels = cipher_a.shape
    pixels_per_channel = height * width
    values_total = pixels_per_channel * channels

    metrics: dict[str, float] = {
        "rgb_npcr_percent": float(changed.sum() / values_total * 100.0),
        "rgb_uaci_percent": float(np.abs(diff).sum() / (255.0 * values_total) * 100.0),
    }
    for index, channel in enumerate(("r", "g", "b")):
        metrics[f"{channel}_npcr_percent"] = float(
            changed[:, :, index].sum() / pixels_per_channel * 100.0
        )
        metrics[f"{channel}_uaci_percent"] = float(
            np.abs(diff[:, :, index]).sum() / (255.0 * pixels_per_channel) * 100.0
        )
    return metrics


def main() -> None:
    input_dir = PROJECT_ROOT / "input" / "uct_colour"
    output_dir = PROJECT_ROOT / "output" / "key_sensitivity"
    output_dir.mkdir(parents=True, exist_ok=True)

    base_key = DEFAULT_DEMO_KEY
    flipped_key = flip_first_key_bit(base_key)

    rows = []
    for filename in FILENAMES:
        image = load_rgb(input_dir / filename)
        for block_size in BLOCK_SIZES:
            if image.shape[0] % block_size or image.shape[1] % block_size:
                continue

            base_params = DemoPipelineParameters(block_size=block_size, key=base_key)
            flipped_params = replace(base_params, key=flipped_key)

            base_result = encrypt_rgb_image(image, PAYLOAD_BITS, base_params)
            flipped_result = encrypt_rgb_image(image, PAYLOAD_BITS, flipped_params)
            metrics = npcr_uaci(base_result.encrypted_image, flipped_result.encrypted_image)

            rows.append(
                {
                    "image": filename,
                    "block_size": block_size,
                    "payload_bits": len(PAYLOAD_BITS),
                    "key_bit_difference": 1,
                    "same_image_identifier": base_result.image_identifier
                    == flipped_result.image_identifier,
                    **metrics,
                }
            )

    csv_path = output_dir / "uct_key_sensitivity_npcr_uaci.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    best = max(rows, key=lambda row: float(row["rgb_uaci_percent"]))
    summary_path = output_dir / "README.md"
    summary_path.write_text(
        "\n".join(
            [
                "# Key-Sensitivity NPCR/UACI",
                "",
                "This folder records a one-bit key-sensitivity check on the six UCT",
                "colour images. For each image and block size, the experiment keeps",
                "the plaintext image, payload, automatic image identifier, and all",
                "parameters fixed, then flips one bit of the 256-bit key and compares",
                "the two ciphertext images.",
                "",
                "This is not the paper's Section 6.8 plaintext-differential table.",
                "",
                "Best RGB UACI in this sweep:",
                f"- image: `{best['image']}`",
                f"- block size: `{best['block_size']}`",
                f"- RGB NPCR: `{best['rgb_npcr_percent']:.6f}%`",
                f"- RGB UACI: `{best['rgb_uaci_percent']:.6f}%`",
                "",
                "The ideal random 8-bit image-cipher reference is approximately",
                "NPCR 99.6094% and UACI 33.4635%, so these results should be",
                "reported as strong pixel-change sensitivity with moderate UACI,",
                "not ideal avalanche behavior.",
                "",
                "Regenerate with:",
                "",
                "```bash",
                "python experiments/key_sensitivity_npcr_uaci.py",
                "```",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(f"wrote {csv_path}")
    print(f"wrote {summary_path}")


if __name__ == "__main__":
    main()
