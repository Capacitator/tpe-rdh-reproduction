"""Small end-to-end demo for Sections 5.2-5.5.

This demo integrates the existing component modules in paper order. It uses
small synthetic RGB data and the current explicit demo assumptions; it does not
add security metrics or optimization.
"""

from pathlib import Path
import sys

import matplotlib.pyplot as plt
import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from pipeline import DemoPipelineParameters, decrypt_rgb_image, encrypt_rgb_image
from rdh import bits_from_bytes, bytes_from_bits


def _make_demo_rgb() -> np.ndarray:
    image = np.zeros((32, 32, 3), dtype=np.uint8)
    image[:, :, 0] = 90
    image[:, :, 1] = 120
    image[:, :, 2] = 150
    image[0, :16, 0] = np.arange(16, dtype=np.uint8)
    image[0, :16, 1] = np.arange(16, dtype=np.uint8) + 1
    image[0, :16, 2] = np.arange(16, dtype=np.uint8) + 2
    image[8:16, 8:16] = [40, 180, 90]
    image[20:28, 3:11] = [210, 50, 160]
    image[4, 4] = [0, 255, 0]
    image[4, 5] = [255, 0, 255]
    return image


def main() -> None:
    """Run the integrated pipeline and save a visual comparison."""

    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    params = DemoPipelineParameters()
    original = _make_demo_rgb()
    payload_bits = bits_from_bytes(b"Sections 5.2-5.5")

    encrypted = encrypt_rgb_image(original, payload_bits, params)
    decrypted = decrypt_rgb_image(encrypted.encrypted_image, params)

    np.save(output_dir / "demo_pipeline_original.npy", original)
    np.save(output_dir / "demo_pipeline_encrypted.npy", encrypted.encrypted_image)
    np.save(output_dir / "demo_pipeline_recovered.npy", decrypted.recovered_image)

    fig, axes = plt.subplots(1, 3, figsize=(9, 3), constrained_layout=True)
    axes[0].imshow(original)
    axes[0].set_title("Original")
    axes[1].imshow(encrypted.encrypted_image)
    axes[1].set_title("Encrypted marked")
    axes[2].imshow(decrypted.recovered_image)
    axes[2].set_title("Recovered")
    for axis in axes:
        axis.set_xticks([])
        axis.set_yticks([])

    output_path = output_dir / "demo_pipeline.png"
    fig.savefig(output_path, dpi=200)

    print("PAPER AMBIGUITY / IMPLEMENTATION DECISION: payload is embedded in channel 0 only.")
    print("PAPER AMBIGUITY / IMPLEMENTATION DECISION: demo discard_count=0.")
    print("PAPER AMBIGUITY / IMPLEMENTATION DECISION: vartheta=10000.0 is inferred from Fig. 4, not explicit text.")
    print(f"Extracted payload: {bytes_from_bits(decrypted.payload_bits)!r}")
    print(f"Recovered exactly: {np.array_equal(original, decrypted.recovered_image)}")
    print(f"Saved demo visualization to {output_path}")


if __name__ == "__main__":
    main()
