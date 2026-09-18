"""Run first Section 6-style quality/security experiments on real RGB images.

This script does not modify the encryption algorithm. It uses the current
tested pipeline and reports validation metrics inspired by Section 6:

- recovery quality: PSNR, SSIM, max absolute recovery error, exact recovery
- adjacent-pixel correlation with 5,000 sampled pairs
- differential metrics: NPCR and UACI
- embedding capacity before and after overhead
- runtime split into encryption+embedding and decryption+recovery

Assumptions/limitations:
- The paper uses the Helen dataset; this script uses local `skimage.data`
  natural RGB images resized/cropped to 512x512, so results are not claimed to
  reproduce the authors' exact numbers.
- Differential attack setup is underspecified in the accessible paper text.
  Here, one pixel per `b x b` block is changed by +/-1 before encrypting the
  second plaintext, matching the paper statement as closely as available text
  permits. The channel policy is explicit below.
- NPCR and UACI are reported per RGB channel with `W * H` normalization, matching
  the paper's Eq. (15)-Eq. (17) image-position formulas. An RGB mean row is also
  written as a convenience summary, but the per-channel rows are the primary
  reproduction data.
- Runtime excludes file I/O and plotting.
- `vartheta=10000.0` is used as a Fig. 4 inference, not an explicit textual
  parameter.
"""

from __future__ import annotations

import csv
from dataclasses import replace
import time
from pathlib import Path
import sys
from typing import Dict, Iterable, List, Tuple

import matplotlib.pyplot as plt
import numpy as np
from skimage import color, data, transform
from skimage.metrics import peak_signal_noise_ratio, structural_similarity


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from pipeline import DemoPipelineParameters, decrypt_rgb_image, encrypt_rgb_image
from rdh import bits_from_bytes, find_histogram_peak_and_zero


BLOCK_SIZES = [8, 16, 32, 64]
IMAGE_NAMES = ["coffee", "chelsea", "rocket", "hubble_deep_field"]
PAIR_COUNT = 5000
PAYLOAD_BITS = bits_from_bytes(b"section6")


def load_real_rgb_images() -> Dict[str, np.ndarray]:
    """Load 3-5 natural RGB images and preprocess each to 512x512 uint8 RGB."""

    # `astronaut` is a natural 512x512 sample, but it currently triggers the
    # paper's underspecified no-zero-point RDH path in a way this implementation
    # rejects as ambiguous. We keep the algorithm unchanged and use four real
    # images that the present RDH implementation can process.
    loaders = {
        "coffee": data.coffee,
        "chelsea": data.chelsea,
        "rocket": data.rocket,
        "hubble_deep_field": data.hubble_deep_field,
    }
    return {name: _to_512_rgb(loader()) for name, loader in loaders.items()}


def _to_512_rgb(image: np.ndarray) -> np.ndarray:
    if image.ndim == 2:
        image = np.stack([image, image, image], axis=2)
    if image.shape[2] == 4:
        image = image[:, :, :3]
    if image.shape[:2] != (512, 512):
        image = transform.resize(
            image,
            (512, 512),
            order=1,
            preserve_range=True,
            anti_aliasing=True,
        )
    return np.rint(image).clip(0, 255).astype(np.uint8)


def recovery_quality(original: np.ndarray, recovered: np.ndarray) -> Dict[str, float]:
    """Compute Section 6.2-style exact-recovery quality metrics."""

    return {
        "psnr": float(peak_signal_noise_ratio(original, recovered, data_range=255)),
        "ssim": float(
            structural_similarity(original, recovered, data_range=255, channel_axis=2)
        ),
        "max_abs_error": int(
            np.abs(original.astype(np.int16) - recovered.astype(np.int16)).max()
        ),
        "exact_recovery": bool(np.array_equal(original, recovered)),
    }


def adjacent_pixel_correlation(
    image: np.ndarray, direction: str, sample_count: int, seed: int
) -> float:
    """Sample adjacent luminance pairs and compute their correlation.

    The paper samples 5,000 adjacent pixel pairs for horizontal, vertical, and
    diagonal directions. This prototype helper currently converts RGB to
    luminance before sampling, so its output should be treated as a validation
    metric rather than a strict reproduction of the paper's per-channel tables.
    We use deterministic random sampling for reproducible validation.
    """

    gray = color.rgb2gray(image).astype(np.float64)
    rng = np.random.default_rng(seed)
    height, width = gray.shape

    if direction == "horizontal":
        rows = rng.integers(0, height, sample_count)
        cols = rng.integers(0, width - 1, sample_count)
        x_values = gray[rows, cols]
        y_values = gray[rows, cols + 1]
    elif direction == "vertical":
        rows = rng.integers(0, height - 1, sample_count)
        cols = rng.integers(0, width, sample_count)
        x_values = gray[rows, cols]
        y_values = gray[rows + 1, cols]
    elif direction == "diagonal":
        rows = rng.integers(0, height - 1, sample_count)
        cols = rng.integers(0, width - 1, sample_count)
        x_values = gray[rows, cols]
        y_values = gray[rows + 1, cols + 1]
    else:
        raise ValueError("direction must be horizontal, vertical, or diagonal")

    if np.std(x_values) == 0 or np.std(y_values) == 0:
        return float("nan")
    return float(np.corrcoef(x_values, y_values)[0, 1])


def make_differential_plaintext(
    image: np.ndarray, block_size: int, channel: int = 0
) -> np.ndarray:
    """Alter one pixel per block for Section 6.8 NPCR/UACI validation.

    Paper reference:
        Section 6.8 says TPE is applied to each block and one pixel value within
        each block is altered to yield two encrypted images. It does not specify
        the exact pixel position, channel, or +/- direction.

    PAPER AMBIGUITY / IMPLEMENTATION DECISION:
        Use the top-left pixel of each block in one selected RGB channel. Change
        by +1 unless the value is already 255, in which case change by -1.
    """

    modified = image.copy()
    for row in range(0, image.shape[0], block_size):
        for col in range(0, image.shape[1], block_size):
            value = int(modified[row, col, channel])
            modified[row, col, channel] = value + 1 if value < 255 else value - 1
    return modified


def npcr_uaci_channel(
    cipher_a: np.ndarray, cipher_b: np.ndarray, channel: int
) -> Tuple[float, float]:
    """Compute Section 6.8 NPCR/UACI for one RGB channel.

    Eq. (17) defines D(i,j) as 1 when ciphertext pixels differ and 0 otherwise.
    Eq. (15) divides the sum of D(i,j) by `W * H`. Eq. (16) divides absolute
    intensity differences by `255 * W * H`.
    """

    a = cipher_a[:, :, channel].astype(np.int16)
    b = cipher_b[:, :, channel].astype(np.int16)
    difference = a != b
    npcr = float(difference.mean() * 100.0)
    uaci = float((np.abs(a - b).mean() / 255.0) * 100.0)
    return npcr, uaci


def npcr_uaci_rows(
    image_name: str,
    block_size: int,
    cipher_a: np.ndarray,
    cipher_b: np.ndarray,
) -> List[Dict[str, object]]:
    """Return per-channel and RGB-mean Section 6.8 metric rows."""

    rows: List[Dict[str, object]] = []
    channel_values = []
    for channel, label in enumerate(["R", "G", "B"]):
        npcr, uaci = npcr_uaci_channel(cipher_a, cipher_b, channel)
        channel_values.append((npcr, uaci))
        rows.append(
            {
                "image": image_name,
                "block_size": block_size,
                "channel": label,
                "npcr_percent": npcr,
                "uaci_percent": uaci,
                "plaintext_change": "top-left pixel in each block changed by +/-1 in R channel",
                "normalization": "per channel W*H, Eqs. (15)-(17)",
            }
        )

    rows.append(
        {
            "image": image_name,
            "block_size": block_size,
            "channel": "RGB_mean",
            "npcr_percent": float(np.mean([value[0] for value in channel_values])),
            "uaci_percent": float(np.mean([value[1] for value in channel_values])),
            "plaintext_change": "top-left pixel in each block changed by +/-1 in R channel",
            "normalization": "mean of per-channel NPCR/UACI rows",
        }
    )
    return rows


def channel_capacity_rows(
    image_name: str,
    block_size: int,
    encrypted_result,
) -> List[Dict[str, object]]:
    """Estimate per-channel RDH capacity before and after overhead."""

    rows: List[Dict[str, object]] = []
    for channel_index, info in enumerate(encrypted_result.rdh_infos):
        carrier = encrypted_result.permuted_image[:, :, channel_index]
        points = find_histogram_peak_and_zero(carrier)
        capacity_before = int(np.count_nonzero(_embedding_mask(carrier.shape) & (carrier == points.peak)))
        overhead_bits = info.embedded_bit_count - info.payload_length
        rows.append(
            {
                "image": image_name,
                "block_size": block_size,
                "channel": channel_index,
                "peak": info.peak,
                "zero": info.zero,
                "has_true_zero": info.has_true_zero,
                "capacity_before_overhead_bits": capacity_before,
                "overhead_bits": overhead_bits,
                "capacity_after_overhead_bits": capacity_before - overhead_bits,
                "payload_bits_embedded": info.payload_length,
            }
        )
    return rows


def _embedding_mask(shape: Tuple[int, int]) -> np.ndarray:
    mask = np.ones(shape, dtype=bool)
    mask[0, :16] = False
    return mask


def write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def plot_metric(
    rows: List[Dict[str, object]],
    y_key: str,
    title: str,
    output_path: Path,
    group_key: str = "image",
) -> None:
    """Create a compact per-image metric plot across block sizes."""

    fig, axis = plt.subplots(figsize=(7, 4), constrained_layout=True)
    groups = sorted({str(row[group_key]) for row in rows})
    for group in groups:
        group_rows = [row for row in rows if str(row[group_key]) == group]
        group_rows.sort(key=lambda row: int(row["block_size"]))
        axis.plot(
            [int(row["block_size"]) for row in group_rows],
            [float(row[y_key]) for row in group_rows],
            marker="o",
            label=group,
        )
    axis.set_title(title)
    axis.set_xlabel("Block size")
    axis.set_ylabel(y_key)
    axis.legend(fontsize=7)
    fig.savefig(output_path, dpi=180)


def plot_correlation(rows: List[Dict[str, object]], output_path: Path) -> None:
    """Plot mean original/encrypted correlation by direction and block size."""

    fig, axes = plt.subplots(1, 3, figsize=(12, 3.5), constrained_layout=True)
    for axis, direction in zip(axes, ["horizontal", "vertical", "diagonal"]):
        direction_rows = [row for row in rows if row["direction"] == direction]
        block_sizes = sorted({int(row["block_size"]) for row in direction_rows})
        original_means = []
        encrypted_means = []
        for block_size in block_sizes:
            block_rows = [
                row for row in direction_rows if int(row["block_size"]) == block_size
            ]
            original_means.append(
                float(np.mean([float(row["original_correlation"]) for row in block_rows]))
            )
            encrypted_means.append(
                float(np.mean([float(row["encrypted_correlation"]) for row in block_rows]))
            )
        axis.plot(block_sizes, original_means, marker="o", label="original")
        axis.plot(block_sizes, encrypted_means, marker="o", label="encrypted")
        axis.set_title(direction)
        axis.set_xlabel("Block size")
        axis.set_ylabel("Correlation")
        axis.legend(fontsize=7)
    fig.savefig(output_path, dpi=180)


def plot_capacity(rows: List[Dict[str, object]], output_path: Path) -> None:
    """Plot total capacity before and after overhead by block size."""

    fig, axis = plt.subplots(figsize=(7, 4), constrained_layout=True)
    block_sizes = sorted({int(row["block_size"]) for row in rows})
    before_totals = []
    after_totals = []
    for block_size in block_sizes:
        block_rows = [row for row in rows if int(row["block_size"]) == block_size]
        before_totals.append(
            sum(int(row["capacity_before_overhead_bits"]) for row in block_rows)
        )
        after_totals.append(
            sum(int(row["capacity_after_overhead_bits"]) for row in block_rows)
        )
    axis.plot(block_sizes, before_totals, marker="o", label="before overhead")
    axis.plot(block_sizes, after_totals, marker="o", label="after overhead")
    axis.set_title("Embedding Capacity")
    axis.set_xlabel("Block size")
    axis.set_ylabel("Bits")
    axis.legend(fontsize=8)
    fig.savefig(output_path, dpi=180)


def run() -> None:
    output_dir = PROJECT_ROOT / "output" / "section6"
    output_dir.mkdir(parents=True, exist_ok=True)

    images = load_real_rgb_images()

    quality_rows: List[Dict[str, object]] = []
    correlation_rows: List[Dict[str, object]] = []
    differential_rows: List[Dict[str, object]] = []
    capacity_rows: List[Dict[str, object]] = []
    runtime_rows: List[Dict[str, object]] = []
    summary_rows: List[Dict[str, object]] = []

    for image_name, image in images.items():
        for block_size in BLOCK_SIZES:
            params = DemoPipelineParameters(block_size=block_size)

            start = time.perf_counter()
            encrypted_result = encrypt_rgb_image(image, PAYLOAD_BITS, params)
            encryption_seconds = time.perf_counter() - start

            start = time.perf_counter()
            decrypted_result = decrypt_rgb_image(
                encrypted_result.encrypted_image,
                replace(params, image_identifier=encrypted_result.image_identifier),
            )
            decryption_seconds = time.perf_counter() - start

            quality = recovery_quality(image, decrypted_result.recovered_image)
            quality_row = {
                "image": image_name,
                "block_size": block_size,
                **quality,
            }
            quality_rows.append(quality_row)

            for direction in ["horizontal", "vertical", "diagonal"]:
                correlation_rows.append(
                    {
                        "image": image_name,
                        "block_size": block_size,
                        "direction": direction,
                        "original_correlation": adjacent_pixel_correlation(
                            image, direction, PAIR_COUNT, seed=block_size
                        ),
                        "encrypted_correlation": adjacent_pixel_correlation(
                            encrypted_result.encrypted_image,
                            direction,
                            PAIR_COUNT,
                            seed=block_size,
                        ),
                        "sample_pairs": PAIR_COUNT,
                    }
                )

            modified = make_differential_plaintext(image, block_size, channel=0)
            modified_cipher = encrypt_rgb_image(modified, PAYLOAD_BITS, params).encrypted_image
            current_differential_rows = npcr_uaci_rows(
                image_name,
                block_size,
                encrypted_result.encrypted_image,
                modified_cipher,
            )
            differential_rows.extend(current_differential_rows)
            mean_differential = next(
                row for row in current_differential_rows if row["channel"] == "RGB_mean"
            )

            capacity_rows.extend(channel_capacity_rows(image_name, block_size, encrypted_result))

            runtime_row = {
                "image": image_name,
                "block_size": block_size,
                "encryption_embedding_seconds": encryption_seconds,
                "decryption_recovery_seconds": decryption_seconds,
                "file_io_included": False,
            }
            runtime_rows.append(runtime_row)

            summary_rows.append(
                {
                    "image": image_name,
                    "block_size": block_size,
                    "psnr": quality["psnr"],
                    "ssim": quality["ssim"],
                    "max_abs_error": quality["max_abs_error"],
                    "exact_recovery": quality["exact_recovery"],
                    "npcr_percent": mean_differential["npcr_percent"],
                    "uaci_percent": mean_differential["uaci_percent"],
                    "encryption_embedding_seconds": encryption_seconds,
                    "decryption_recovery_seconds": decryption_seconds,
                }
            )

            print(
                f"{image_name} b={block_size}: exact={quality['exact_recovery']} "
                f"PSNR={quality['psnr']} SSIM={quality['ssim']:.6f} "
                f"NPCR={float(mean_differential['npcr_percent']):.3f}% "
                f"UACI={float(mean_differential['uaci_percent']):.3f}%"
            )

    write_csv(output_dir / "quality_metrics.csv", quality_rows)
    write_csv(output_dir / "correlation_metrics.csv", correlation_rows)
    write_csv(output_dir / "differential_metrics.csv", differential_rows)
    write_csv(output_dir / "capacity_metrics.csv", capacity_rows)
    write_csv(output_dir / "runtime_metrics.csv", runtime_rows)
    write_csv(output_dir / "summary_metrics.csv", summary_rows)

    plot_metric(quality_rows, "ssim", "Recovery SSIM", output_dir / "plot_recovery_ssim.png")
    plot_metric(
        quality_rows,
        "max_abs_error",
        "Maximum Absolute Recovery Error",
        output_dir / "plot_recovery_max_abs_error.png",
    )
    plot_correlation(correlation_rows, output_dir / "plot_correlation.png")
    plot_metric(differential_rows, "npcr_percent", "NPCR", output_dir / "plot_npcr.png")
    plot_metric(differential_rows, "uaci_percent", "UACI", output_dir / "plot_uaci.png")
    plot_capacity(capacity_rows, output_dir / "plot_capacity.png")
    plot_metric(
        runtime_rows,
        "encryption_embedding_seconds",
        "Encryption + Embedding Time",
        output_dir / "plot_encryption_time.png",
    )
    plot_metric(
        runtime_rows,
        "decryption_recovery_seconds",
        "Decryption + Recovery Time",
        output_dir / "plot_decryption_time.png",
    )

    print(f"saved_dir={output_dir}")


if __name__ == "__main__":
    run()
