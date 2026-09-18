"""Run the current pipeline on all six UCT colour images for b=8,16,32,64.

This script is an experiment/output runner only. It does not modify or extend
the encryption algorithm; it calls the existing validated pipeline and records
whether each run is exactly reversible.
"""

from __future__ import annotations

import csv
from dataclasses import replace
from pathlib import Path
import sys

import cv2
import numpy as np
from PIL import Image


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from pipeline import DemoPipelineParameters, block_sums, decrypt_rgb_image, encrypt_rgb_image
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
PAYLOAD = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes = 256 bits
PAYLOAD_BITS = bits_from_bytes(PAYLOAD)


def load_rgb(path: Path) -> np.ndarray:
    """Load one UCT colour TIF as a channel-last uint8 RGB array."""

    image = cv2.imread(str(path), cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError(f"could not read image: {path}")
    return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)


def save_rgb(path: Path, image: np.ndarray) -> None:
    """Save a channel-last RGB array as PNG."""

    Image.fromarray(image, mode="RGB").save(path)


def main() -> None:
    input_dir = PROJECT_ROOT / "input" / "uct_colour"
    output_dir = PROJECT_ROOT / "output" / "uct_colour_all_blocks"
    output_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for filename in FILENAMES:
        image = load_rgb(input_dir / filename)
        stem = Path(filename).stem

        for block_size in BLOCK_SIZES:
            case_dir = output_dir / stem / f"b{block_size}"
            case_dir.mkdir(parents=True, exist_ok=True)
            params = DemoPipelineParameters(block_size=block_size)

            encrypted = encrypt_rgb_image(image, PAYLOAD_BITS, params)
            decrypted = decrypt_rgb_image(
                encrypted.encrypted_image,
                replace(params, image_identifier=encrypted.image_identifier),
            )

            max_recovery_error = int(
                np.abs(image.astype(np.int16) - decrypted.recovered_image.astype(np.int16)).max()
            )
            exact_recovery = bool(np.array_equal(image, decrypted.recovered_image))
            payload_recovered = bool(decrypted.payload_bits == PAYLOAD_BITS)
            block_sum_preserved = bool(
                np.array_equal(
                    block_sums(encrypted.marked_image, block_size),
                    block_sums(encrypted.encrypted_image, block_size),
                )
            )

            save_rgb(case_dir / "final_encrypted.png", encrypted.encrypted_image)
            save_rgb(case_dir / "recovered.png", decrypted.recovered_image)

            rows.append(
                {
                    "image": filename,
                    "width": image.shape[1],
                    "height": image.shape[0],
                    "block_size": block_size,
                    "exact_recovery": exact_recovery,
                    "max_recovery_error": max_recovery_error,
                    "payload_recovered": payload_recovered,
                    "block_sum_preserved": block_sum_preserved,
                }
            )
            print(
                f"{filename} b={block_size}: exact={exact_recovery} "
                f"max_error={max_recovery_error} payload={payload_recovered} "
                f"block_sum={block_sum_preserved}"
            )

    summary_path = output_dir / "summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "image",
                "width",
                "height",
                "block_size",
                "exact_recovery",
                "max_recovery_error",
                "payload_recovered",
                "block_sum_preserved",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    successful = sum(
        row["exact_recovery"] and row["payload_recovered"] and row["block_sum_preserved"]
        for row in rows
    )
    print(f"total_runs={len(rows)}")
    print(f"successful_runs={successful}")
    print(f"failed_runs={len(rows) - successful}")
    print(f"summary_csv={summary_path}")


if __name__ == "__main__":
    main()
