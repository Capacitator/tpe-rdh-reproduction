"""Run the current pipeline on all six UCT colour standard images.

Source page:
https://www.dip.ee.uct.ac.za/imageproc/stdimages/colour/

The page lists exactly six full-size colour files:
airplane.tif, baboon.tif, couple.tif, girl.tif, lena.tif, peppers.tif.

This script does not modify the encryption algorithm. It loads the downloaded
files from `input/uct_colour`, runs the current end-to-end pipeline, and writes
a compact processing summary.
"""

from __future__ import annotations

import csv
from dataclasses import replace
import time
from pathlib import Path
import sys

import cv2
import numpy as np
from skimage.metrics import peak_signal_noise_ratio, structural_similarity


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from pipeline import DemoPipelineParameters, decrypt_rgb_image, encrypt_rgb_image
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
PAYLOAD_BITS = bits_from_bytes(b"UCT colour validation")


def load_rgb(path: Path) -> np.ndarray:
    """Load a source TIF as uint8 RGB without changing the algorithm."""

    image = cv2.imread(str(path), cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError(f"could not read image: {path}")
    return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)


def main() -> None:
    input_dir = PROJECT_ROOT / "input" / "uct_colour"
    output_dir = PROJECT_ROOT / "output" / "uct_colour"
    output_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for filename in FILENAMES:
        image = load_rgb(input_dir / filename)
        for block_size in BLOCK_SIZES:
            params = DemoPipelineParameters(block_size=block_size)

            start = time.perf_counter()
            encrypted = encrypt_rgb_image(image, PAYLOAD_BITS, params)
            encryption_seconds = time.perf_counter() - start

            start = time.perf_counter()
            decrypted = decrypt_rgb_image(
                encrypted.encrypted_image,
                replace(params, image_identifier=encrypted.image_identifier),
            )
            decryption_seconds = time.perf_counter() - start

            max_error = int(
                np.abs(image.astype(np.int16) - decrypted.recovered_image.astype(np.int16)).max()
            )
            exact = bool(np.array_equal(image, decrypted.recovered_image))
            payload_exact = decrypted.payload_bits == PAYLOAD_BITS
            psnr = peak_signal_noise_ratio(image, decrypted.recovered_image, data_range=255)
            ssim = structural_similarity(
                image, decrypted.recovered_image, data_range=255, channel_axis=2
            )

            rows.append(
                {
                    "filename": filename,
                    "height": image.shape[0],
                    "width": image.shape[1],
                    "block_size": block_size,
                    "exact_recovery": exact,
                    "payload_exact": payload_exact,
                    "max_abs_error": max_error,
                    "psnr": float(psnr),
                    "ssim": float(ssim),
                    "encryption_seconds": encryption_seconds,
                    "decryption_seconds": decryption_seconds,
                    "vartheta": params.vartheta,
                }
            )
            print(
                f"{filename} b={block_size}: exact={exact} payload={payload_exact} "
                f"max_error={max_error}"
            )

    summary_path = output_dir / "uct_colour_pipeline_summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"saved_summary={summary_path}")


if __name__ == "__main__":
    main()
