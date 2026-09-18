"""Create b=16 stage outputs for the six UCT colour test images.

Source:
https://www.dip.ee.uct.ac.za/imageproc/stdimages/colour/

This experiment does not modify the encryption algorithm. It runs the current
complete pipeline on the six actual colour files from the page, embeds the same
256-bit payload in each run, and saves original/final/recovered images plus a
comparison figure.
"""

from __future__ import annotations

import csv
from dataclasses import replace
from pathlib import Path
import sys

import cv2
import matplotlib.pyplot as plt
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
BLOCK_SIZE = 16
PAYLOAD = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes = 256 bits
PAYLOAD_BITS = bits_from_bytes(PAYLOAD)


def load_rgb(path: Path) -> np.ndarray:
    """Load a UCT TIF as channel-last uint8 RGB."""

    image = cv2.imread(str(path), cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError(f"could not read image: {path}")
    return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)


def save_rgb(path: Path, image: np.ndarray) -> None:
    """Save a channel-last RGB array."""

    Image.fromarray(image, mode="RGB").save(path)


def save_comparison(path: Path, original: np.ndarray, encrypted: np.ndarray, recovered: np.ndarray) -> None:
    """Save a simple original/final/recovered comparison figure."""

    fig, axes = plt.subplots(1, 3, figsize=(9, 3.2), constrained_layout=True)
    for axis, title, image in zip(
        axes,
        ["Original", "Final encrypted", "Recovered"],
        [original, encrypted, recovered],
    ):
        axis.imshow(image)
        axis.set_title(title)
        axis.set_xticks([])
        axis.set_yticks([])
    fig.savefig(path, dpi=180)
    plt.close(fig)


def main() -> None:
    input_dir = PROJECT_ROOT / "input" / "uct_colour"
    output_dir = PROJECT_ROOT / "output" / "uct_colour_b16"
    output_dir.mkdir(parents=True, exist_ok=True)

    params = DemoPipelineParameters(block_size=BLOCK_SIZE)
    rows = []

    for filename in FILENAMES:
        image = load_rgb(input_dir / filename)
        stem = Path(filename).stem
        image_dir = output_dir / stem
        image_dir.mkdir(parents=True, exist_ok=True)

        error = ""
        try:
            encrypted = encrypt_rgb_image(image, PAYLOAD_BITS, params)
            decrypted = decrypt_rgb_image(
                encrypted.encrypted_image,
                replace(params, image_identifier=encrypted.image_identifier),
            )

            exact_recovery = bool(np.array_equal(image, decrypted.recovered_image))
            max_recovery_error = int(
                np.abs(image.astype(np.int16) - decrypted.recovered_image.astype(np.int16)).max()
            )
            payload_recovery = decrypted.payload_bits == PAYLOAD_BITS
            post_rdh_block_sum_preservation = bool(
                np.array_equal(
                    block_sums(encrypted.marked_image, BLOCK_SIZE),
                    block_sums(encrypted.encrypted_image, BLOCK_SIZE),
                )
            )

            save_rgb(image_dir / "original.png", image)
            save_rgb(image_dir / "final_encrypted.png", encrypted.encrypted_image)
            save_rgb(image_dir / "recovered.png", decrypted.recovered_image)
            save_comparison(
                image_dir / "comparison.png",
                image,
                encrypted.encrypted_image,
                decrypted.recovered_image,
            )
        except Exception as exc:
            exact_recovery = False
            max_recovery_error = ""
            payload_recovery = False
            post_rdh_block_sum_preservation = False
            error = f"{type(exc).__name__}: {exc}"

        rows.append(
            {
                "image": filename,
                "height": image.shape[0],
                "width": image.shape[1],
                "channels": image.shape[2],
                "dtype": str(image.dtype),
                "block_size": BLOCK_SIZE,
                "payload_bits": len(PAYLOAD_BITS),
                "exact_recovery": exact_recovery,
                "max_recovery_error": max_recovery_error,
                "payload_recovery": payload_recovery,
                "post_rdh_block_sum_preservation": post_rdh_block_sum_preservation,
                "error": error,
                "output_folder": image_dir.relative_to(PROJECT_ROOT).as_posix(),
            }
        )

    summary_path = output_dir / "summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"summary={summary_path}")
    for row in rows:
        print(
            f"{row['image']},{row['height']}x{row['width']}x{row['channels']},"
            f"{row['dtype']},exact={row['exact_recovery']},"
            f"payload={row['payload_recovery']},"
            f"block_sums={row['post_rdh_block_sum_preservation']},"
            f"error={row['error'] or 'none'}"
        )


if __name__ == "__main__":
    main()
