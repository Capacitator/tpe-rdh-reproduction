"""Small Section 5.2 permutation demo.

This script uses an already-generated `Upsilon_P` if available in `output/`.
It does not implement RDH, substitution, or the full encryption pipeline.
"""

from pathlib import Path
import sys

import matplotlib.pyplot as plt
import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from chaos import generate_upsilon_matrices
from permutation import inverse_permute_image_blocks, permute_image_blocks

DEMO_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
    "102132435465768798a9babbdcedfe0f"
)
DEMO_IDENTIFIER = b"demo-permutation-image"


def _make_demo_image(height: int, width: int) -> np.ndarray:
    """Create a tiny RGB image with visible structure for permutation checks."""

    rows, cols = np.indices((height, width))
    red = rows * 32
    green = cols * 32
    blue = ((rows + cols) % 2) * 180 + 40
    return np.stack([red, green, blue], axis=2).astype(np.uint8)


def main() -> None:
    """Run a small permutation/inverse-permutation demonstration."""

    height = 8
    width = 8
    block_size = 4
    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    upsilon_path = output_dir / "demo_upsilon_p.npy"
    if upsilon_path.exists():
        upsilon_p = np.load(upsilon_path)
    else:
        upsilon_p, _ = generate_upsilon_matrices(
            height, width, DEMO_KEY, DEMO_IDENTIFIER
        )
        np.save(upsilon_path, upsilon_p)

    image = _make_demo_image(height, width)
    permuted = permute_image_blocks(image, upsilon_p, block_size)
    recovered = inverse_permute_image_blocks(permuted, upsilon_p, block_size)

    np.save(output_dir / "demo_permuted_image.npy", permuted)
    np.save(output_dir / "demo_recovered_after_inverse_permutation.npy", recovered)

    fig, axes = plt.subplots(1, 3, figsize=(9, 3), constrained_layout=True)
    axes[0].imshow(image)
    axes[0].set_title("Original")
    axes[1].imshow(permuted)
    axes[1].set_title("Permuted")
    axes[2].imshow(recovered)
    axes[2].set_title("Recovered")
    for axis in axes:
        axis.set_xticks([])
        axis.set_yticks([])

    output_path = output_dir / "demo_permutation.png"
    fig.savefig(output_path, dpi=200)

    print(f"Loaded Upsilon_P from {upsilon_path}")
    print("PAPER AMBIGUITY: row-major stable ascending sort is documented in src/permutation.py")
    print(f"Recovered exactly: {np.array_equal(image, recovered)}")
    print(f"Saved demo visualization to {output_path}")


if __name__ == "__main__":
    main()
