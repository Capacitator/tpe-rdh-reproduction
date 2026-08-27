"""Validate thumbnail/block-sum behavior for the current integrated pipeline.

Thumbnail preservation is driven by sum preservation: if every `b x b` block
keeps the same per-channel sum, then replacing each block by its average color
produces the same thumbnail value for that block.

This experiment separates the two effects that happen after permutation:

1. RDH can change block sums while embedding metadata/payload.
2. Substitution must preserve the RDH-adjusted block sums exactly.

The critical assertion is therefore:

    RDH/marked block sum == final encrypted block sum
"""

from __future__ import annotations

import csv
from pathlib import Path
import sys
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt
import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from pipeline import DemoPipelineParameters, encrypt_rgb_image
from rdh import bits_from_bytes


BLOCK_SIZES = [8, 16, 32, 64]


def make_test_rgb_image(size: int = 64) -> np.ndarray:
    """Create one deterministic RGB image with enough repeated values for RDH."""

    image = np.zeros((size, size, 3), dtype=np.uint8)
    image[:, :, 0] = 90
    image[:, :, 1] = 120
    image[:, :, 2] = 150

    # Preserve a visible structure while keeping strong histogram peaks so the
    # existing RDH component has enough capacity for metadata and payload.
    image[8:24, 8:24] = [40, 180, 90]
    image[32:50, 6:24] = [210, 50, 160]
    image[20:44, 38:56] = [70, 200, 230]
    image[4, 4] = [0, 255, 0]
    image[4, 5] = [255, 0, 255]

    # RDH uses the first 16 top-row LSBs for P/Z storage, so vary those pixels
    # to exercise the overhead recovery path during the full pipeline run.
    for channel in range(3):
        image[0, :16, channel] = np.arange(16, dtype=np.uint8) + channel

    return image


def block_sum_differences(
    before: np.ndarray, after: np.ndarray, block_size: int, stage: str
) -> Tuple[List[Dict[str, int]], int, float, bool]:
    """Calculate per-block/channel absolute sum differences."""

    rows: List[Dict[str, int]] = []
    differences: List[int] = []

    for row in range(0, before.shape[0], block_size):
        for col in range(0, before.shape[1], block_size):
            for channel in range(3):
                before_sum = int(
                    before[row : row + block_size, col : col + block_size, channel].sum()
                )
                after_sum = int(
                    after[row : row + block_size, col : col + block_size, channel].sum()
                )
                difference = abs(before_sum - after_sum)
                differences.append(difference)
                rows.append(
                    {
                        "stage": stage,
                        "block_size": block_size,
                        "block_row": row,
                        "block_col": col,
                        "channel": channel,
                        "before_sum": before_sum,
                        "after_sum": after_sum,
                        "abs_difference": difference,
                    }
                )

    max_difference = max(differences)
    mean_difference = float(np.mean(differences))
    exact = all(difference == 0 for difference in differences)
    return rows, max_difference, mean_difference, exact


def block_average_thumbnail(image: np.ndarray, block_size: int) -> np.ndarray:
    """Return a block-average thumbnail expanded for visual comparison."""

    thumb = np.empty_like(image)
    for row in range(0, image.shape[0], block_size):
        for col in range(0, image.shape[1], block_size):
            block = image[row : row + block_size, col : col + block_size]
            average = np.rint(block.mean(axis=(0, 1))).astype(np.uint8)
            thumb[row : row + block_size, col : col + block_size] = average
    return thumb


def save_thumbnail_figure(
    thumbnails: List[Tuple[int, np.ndarray, np.ndarray, np.ndarray]], output_path: Path
) -> None:
    """Save original/RDH-adjusted/final-encrypted thumbnail comparisons."""

    fig, axes = plt.subplots(
        len(thumbnails), 3, figsize=(9, 11), constrained_layout=True
    )
    for row_index, (
        block_size,
        original_thumb,
        marked_thumb,
        encrypted_thumb,
    ) in enumerate(thumbnails):
        axes[row_index, 0].imshow(original_thumb)
        axes[row_index, 0].set_title(f"Original thumbnail b={block_size}")
        axes[row_index, 1].imshow(marked_thumb)
        axes[row_index, 1].set_title(f"RDH thumbnail b={block_size}")
        axes[row_index, 2].imshow(encrypted_thumb)
        axes[row_index, 2].set_title(f"Encrypted thumbnail b={block_size}")
        for axis in axes[row_index]:
            axis.set_xticks([])
            axis.set_yticks([])
    fig.savefig(output_path, dpi=200)


def main() -> None:
    """Run thumbnail validation for block sizes 8, 16, 32, and 64."""

    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    original = make_test_rgb_image()
    payload_bits = bits_from_bytes(b"thumbnail")

    all_rows: List[Dict[str, int]] = []
    summary_rows = []
    thumbnail_sets = []

    for block_size in BLOCK_SIZES:
        params = DemoPipelineParameters(block_size=block_size)
        encrypted_result = encrypt_rgb_image(original, payload_bits, params)
        encrypted = encrypted_result.encrypted_image
        marked = encrypted_result.marked_image
        permuted = encrypted_result.permuted_image

        rdh_rows, rdh_max, rdh_mean, rdh_exact = block_sum_differences(
            permuted, marked, block_size, "rdh"
        )
        substitution_rows, substitution_max, substitution_mean, substitution_exact = (
            block_sum_differences(marked, encrypted, block_size, "substitution")
        )
        all_rows.extend(rdh_rows)
        all_rows.extend(substitution_rows)
        summary_rows.append(
            (block_size, rdh_max, rdh_mean, rdh_exact, substitution_max, substitution_mean, substitution_exact)
        )

        thumbnail_sets.append(
            (
                block_size,
                block_average_thumbnail(original, block_size),
                block_average_thumbnail(marked, block_size),
                block_average_thumbnail(encrypted, block_size),
            )
        )

    metrics_path = output_dir / "thumbnail_metrics.csv"
    with metrics_path.open("w", newline="", encoding="utf-8") as csv_file:
        fieldnames = [
            "stage",
            "block_size",
            "block_row",
            "block_col",
            "channel",
            "before_sum",
            "after_sum",
            "abs_difference",
        ]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    figure_path = output_dir / "thumbnail_validation.png"
    save_thumbnail_figure(thumbnail_sets, figure_path)

    print("test_image=synthetic 64x64 RGB image")
    print(
        "block_size,rdh_max_diff,rdh_mean_diff,rdh_exact,"
        "substitution_max_diff,substitution_mean_diff,substitution_exact"
    )
    for (
        block_size,
        rdh_max,
        rdh_mean,
        rdh_exact,
        substitution_max,
        substitution_mean,
        substitution_exact,
    ) in summary_rows:
        print(
            f"{block_size},{rdh_max},{rdh_mean:.6f},{rdh_exact},"
            f"{substitution_max},{substitution_mean:.6f},{substitution_exact}"
        )
    print(f"saved_metrics={metrics_path}")
    print(f"saved_figure={figure_path}")


if __name__ == "__main__":
    main()
