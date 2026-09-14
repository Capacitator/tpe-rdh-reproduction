"""Generate clean submission-ready results for the current implementation.

The script uses a deterministic synthetic RGB image so the demonstration is
reproducible and does not depend on external image licensing. It calls the
existing encryption/decryption pipeline without changing the algorithm.
"""

from __future__ import annotations

from datetime import datetime, timezone
import platform
from pathlib import Path
import subprocess
import sys
import time
from typing import Tuple

import numpy as np
from PIL import Image
from skimage.metrics import peak_signal_noise_ratio, structural_similarity


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from pipeline import DemoPipelineParameters, block_sums, decrypt_rgb_image, encrypt_rgb_image
from rdh import bits_from_bytes


BLOCK_SIZE = 16
PAYLOAD = b"TPE-RDH submission demo payload"


def current_git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def pinned_requirements() -> str:
    requirements_path = PROJECT_ROOT / "requirements.txt"
    return ", ".join(
        line.strip()
        for line in requirements_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    )


def make_submission_image(size: int = 512) -> np.ndarray:
    """Create a deterministic RGB image with visible structure and RDH capacity."""

    image = np.zeros((size, size, 3), dtype=np.uint8)
    image[:, :, 0] = 92
    image[:, :, 1] = 126
    image[:, :, 2] = 154

    # Large flat regions provide histogram peaks for RDH while still making the
    # image visually meaningful in the generated result figure.
    image[48:208, 44:220] = [38, 172, 94]
    image[260:450, 52:238] = [212, 62, 160]
    image[116:372, 310:470] = [74, 204, 226]

    for row in range(size):
        image[row, :, 0] = np.maximum(image[row, :, 0], 40 + row // 8).astype(np.uint8)
    for col in range(size):
        image[:, col, 1] = np.maximum(image[:, col, 1], 35 + col // 7).astype(np.uint8)

    # Exercise the P/Z LSB storage recovery path.
    for channel in range(3):
        image[0, :16, channel] = np.arange(16, dtype=np.uint8) + channel

    image[12, 20] = [0, 255, 0]
    image[12, 21] = [255, 0, 255]
    return image


def save_rgb(path: Path, image: np.ndarray) -> None:
    Image.fromarray(image, mode="RGB").save(path)


def block_average_thumbnail(image: np.ndarray, block_size: int) -> np.ndarray:
    """Return an expanded block-average thumbnail for visual inspection."""

    thumbnail = np.empty_like(image)
    for row in range(0, image.shape[0], block_size):
        for col in range(0, image.shape[1], block_size):
            block = image[row : row + block_size, col : col + block_size]
            average = np.rint(block.mean(axis=(0, 1))).astype(np.uint8)
            thumbnail[row : row + block_size, col : col + block_size] = average
    return thumbnail


def compact_thumbnail(image: np.ndarray, block_size: int) -> np.ndarray:
    """Return the true compact thumbnail with one pixel per block."""

    height, width = image.shape[:2]
    thumb = np.empty((height // block_size, width // block_size, 3), dtype=np.uint8)
    for out_row, row in enumerate(range(0, height, block_size)):
        for out_col, col in enumerate(range(0, width, block_size)):
            block = image[row : row + block_size, col : col + block_size]
            thumb[out_row, out_col] = np.rint(block.mean(axis=(0, 1))).astype(np.uint8)
    return thumb


def mse(a: np.ndarray, b: np.ndarray) -> float:
    difference = a.astype(np.float64) - b.astype(np.float64)
    return float(np.mean(difference * difference))


def entropy(image: np.ndarray) -> float:
    hist = np.bincount(image.reshape(-1), minlength=256).astype(np.float64)
    probabilities = hist[hist > 0] / hist.sum()
    return float(-np.sum(probabilities * np.log2(probabilities)))


def channel_correlation(image: np.ndarray, direction: str) -> float:
    """Compute adjacent-pixel correlation over all RGB channels."""

    values = image.astype(np.float64)
    if direction == "horizontal":
        x = values[:, :-1, :].reshape(-1)
        y = values[:, 1:, :].reshape(-1)
    elif direction == "vertical":
        x = values[:-1, :, :].reshape(-1)
        y = values[1:, :, :].reshape(-1)
    elif direction == "diagonal":
        x = values[:-1, :-1, :].reshape(-1)
        y = values[1:, 1:, :].reshape(-1)
    else:
        raise ValueError("direction must be horizontal, vertical, or diagonal")

    if np.std(x) == 0 or np.std(y) == 0:
        return float("nan")
    return float(np.corrcoef(x, y)[0, 1])


def thumbnail_max_abs_difference(a: np.ndarray, b: np.ndarray) -> int:
    return int(np.abs(a.astype(np.int16) - b.astype(np.int16)).max())


def run() -> None:
    output_dir = PROJECT_ROOT / "results"
    output_dir.mkdir(parents=True, exist_ok=True)

    params = DemoPipelineParameters(block_size=BLOCK_SIZE)
    payload_bits = bits_from_bytes(PAYLOAD)
    original = make_submission_image()

    start = time.perf_counter()
    encrypted_result = encrypt_rgb_image(original, payload_bits, params)
    encryption_seconds = time.perf_counter() - start

    start = time.perf_counter()
    decrypted_result = decrypt_rgb_image(encrypted_result.encrypted_image, params)
    decryption_seconds = time.perf_counter() - start

    encrypted = encrypted_result.encrypted_image
    recovered = decrypted_result.recovered_image

    original_thumbnail = compact_thumbnail(original, BLOCK_SIZE)
    marked_thumbnail = compact_thumbnail(encrypted_result.marked_image, BLOCK_SIZE)
    encrypted_thumbnail = compact_thumbnail(encrypted, BLOCK_SIZE)
    expanded_encrypted_thumbnail = block_average_thumbnail(encrypted, BLOCK_SIZE)

    exact_recovery = bool(np.array_equal(original, recovered))
    payload_recovered = bool(decrypted_result.payload_bits == payload_bits)
    marked_to_encrypted_block_sums = bool(
        np.array_equal(
            block_sums(encrypted_result.marked_image, BLOCK_SIZE),
            block_sums(encrypted, BLOCK_SIZE),
        )
    )

    save_rgb(output_dir / "original.png", original)
    save_rgb(output_dir / "encrypted.png", encrypted)
    save_rgb(output_dir / "thumbnail.png", expanded_encrypted_thumbnail)
    save_rgb(output_dir / "decrypted.png", recovered)

    metrics = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_commit_at_generation": current_git_commit(),
        "python_version": platform.python_version(),
        "requirements": pinned_requirements(),
        "image": "deterministic synthetic RGB image",
        "image_shape": str(original.shape),
        "block_size": BLOCK_SIZE,
        "thumbnail_shape": str(original_thumbnail.shape),
        "payload_bytes": len(PAYLOAD),
        "payload_bits": len(payload_bits),
        "payload_recovered": payload_recovered,
        "exact_recovery": exact_recovery,
        "max_abs_error": int(
            np.abs(original.astype(np.int16) - recovered.astype(np.int16)).max()
        ),
        "mse_original_recovered": mse(original, recovered),
        "psnr_original_recovered": float(
            peak_signal_noise_ratio(original, recovered, data_range=255)
        ),
        "ssim_original_recovered": float(
            structural_similarity(original, recovered, data_range=255, channel_axis=2)
        ),
        "entropy_original": entropy(original),
        "entropy_encrypted": entropy(encrypted),
        "correlation_original_horizontal": channel_correlation(original, "horizontal"),
        "correlation_encrypted_horizontal": channel_correlation(encrypted, "horizontal"),
        "correlation_original_vertical": channel_correlation(original, "vertical"),
        "correlation_encrypted_vertical": channel_correlation(encrypted, "vertical"),
        "correlation_original_diagonal": channel_correlation(original, "diagonal"),
        "correlation_encrypted_diagonal": channel_correlation(encrypted, "diagonal"),
        "rdh_channel0_peak": encrypted_result.rdh_infos[0].peak,
        "rdh_channel0_zero": encrypted_result.rdh_infos[0].zero,
        "rdh_channel0_payload_bits": encrypted_result.rdh_infos[0].payload_length,
        "rdh_channel0_embedded_bits_including_overhead": encrypted_result.rdh_infos[
            0
        ].embedded_bit_count,
        "marked_to_encrypted_block_sums_preserved": marked_to_encrypted_block_sums,
        "thumbnail_max_abs_difference_marked_vs_encrypted": thumbnail_max_abs_difference(
            marked_thumbnail, encrypted_thumbnail
        ),
        "thumbnail_max_abs_difference_original_vs_encrypted": thumbnail_max_abs_difference(
            original_thumbnail, encrypted_thumbnail
        ),
        "encryption_embedding_seconds": encryption_seconds,
        "decryption_recovery_seconds": decryption_seconds,
    }

    metrics_lines = [
        "Submission result metrics",
        "",
        "These values are generated by experiments/generate_submission_results.py.",
        "They are not fabricated and are not claimed to be the paper authors' official numbers.",
        "",
    ]
    metrics_lines.extend(f"{key}: {value}" for key, value in metrics.items())
    (output_dir / "metrics.txt").write_text("\n".join(metrics_lines) + "\n", encoding="utf-8")

    print("\n".join(metrics_lines))
    print(f"saved_dir={output_dir}")


if __name__ == "__main__":
    run()
