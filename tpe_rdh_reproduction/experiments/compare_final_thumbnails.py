"""Compare original and final encrypted thumbnails for selected block sizes.

This is a visualization/measurement experiment only. It uses the existing
pipeline unchanged and compares block-average thumbnails, because thumbnail
preservation is expressed through per-block average color/sum.
"""

from __future__ import annotations

import csv
from pathlib import Path
import sys

import matplotlib.pyplot as plt
import numpy as np
from skimage.metrics import peak_signal_noise_ratio, structural_similarity


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "experiments"))

from pipeline import DemoPipelineParameters, encrypt_rgb_image
from rdh import bits_from_bytes
from validate_thumbnail import block_average_thumbnail, make_test_rgb_image


BLOCK_SIZES = [8, 16, 32, 64]


def main() -> None:
    """Save original/final encrypted thumbnail comparison and metrics."""

    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    original = make_test_rgb_image()
    payload_bits = bits_from_bytes(b"thumbnail")

    encrypted_thumbnails = []
    metric_rows = []

    for block_size in BLOCK_SIZES:
        params = DemoPipelineParameters(block_size=block_size)
        encrypted = encrypt_rgb_image(original, payload_bits, params).encrypted_image

        original_thumb = block_average_thumbnail(original, block_size)
        encrypted_thumb = block_average_thumbnail(encrypted, block_size)
        encrypted_thumbnails.append((block_size, encrypted_thumb))

        psnr = peak_signal_noise_ratio(original_thumb, encrypted_thumb, data_range=255)
        ssim = structural_similarity(
            original_thumb,
            encrypted_thumb,
            data_range=255,
            channel_axis=2,
        )
        metric_rows.append(
            {"block_size": block_size, "psnr": float(psnr), "ssim": float(ssim)}
        )

    figure_path = output_dir / "final_thumbnail_comparison.png"
    fig, axes = plt.subplots(1, 5, figsize=(13, 3), constrained_layout=True)
    axes[0].imshow(original)
    axes[0].set_title("Original")
    for axis, (block_size, thumbnail) in zip(axes[1:], encrypted_thumbnails):
        axis.imshow(thumbnail)
        axis.set_title(f"b={block_size}")
    for axis in axes:
        axis.set_xticks([])
        axis.set_yticks([])
    fig.savefig(figure_path, dpi=200)

    metrics_path = output_dir / "final_thumbnail_metrics.csv"
    with metrics_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["block_size", "psnr", "ssim"])
        writer.writeheader()
        writer.writerows(metric_rows)

    print("block_size,psnr,ssim")
    for row in metric_rows:
        print(f"{row['block_size']},{row['psnr']:.6f},{row['ssim']:.6f}")
    print(f"saved_figure={figure_path}")
    print(f"saved_metrics={metrics_path}")


if __name__ == "__main__":
    main()
