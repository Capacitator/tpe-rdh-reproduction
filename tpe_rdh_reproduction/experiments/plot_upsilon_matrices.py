"""Create and visualize small Section 5.1 chaotic matrices.

This script deliberately does not implement Section 5.2 permutation or Section
5.4 substitution. It only creates the two key/image-dependent matrices that
will later control those stages.
"""

from pathlib import Path
import sys

import matplotlib.pyplot as plt
import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from chaos import generate_upsilon_matrices

DEMO_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
    "102132435465768798a9babbdcedfe0f"
)
DEMO_IDENTIFIER = b"demo-upsilon-image"


def main() -> None:
    """Generate small `Upsilon_P` and `Upsilon_S` matrices and heatmaps."""

    height = 8
    width = 8

    upsilon_p, upsilon_s = generate_upsilon_matrices(
        height=height,
        width=width,
        key=DEMO_KEY,
        image_identifier=DEMO_IDENTIFIER,
    )

    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    np.save(output_dir / "demo_upsilon_p.npy", upsilon_p)
    np.save(output_dir / "demo_upsilon_s.npy", upsilon_s)

    fig, axes = plt.subplots(1, 2, figsize=(9, 4), constrained_layout=True)

    p_image = axes[0].imshow(upsilon_p, cmap="viridis")
    axes[0].set_title("Demo Upsilon_P")
    axes[0].set_xlabel("Column")
    axes[0].set_ylabel("Row")
    fig.colorbar(p_image, ax=axes[0], fraction=0.046)

    s_image = axes[1].imshow(upsilon_s, cmap="magma")
    axes[1].set_title("Demo Upsilon_S")
    axes[1].set_xlabel("Column")
    axes[1].set_ylabel("Row")
    fig.colorbar(s_image, ax=axes[1], fraction=0.046)

    output_path = output_dir / "demo_upsilon_matrices.png"
    fig.savefig(output_path, dpi=200)

    print("Created demo matrices with the documented key/T convention.")
    print(f"Saved Upsilon_P to {output_dir / 'demo_upsilon_p.npy'}")
    print(f"Saved Upsilon_S to {output_dir / 'demo_upsilon_s.npy'}")
    print(f"Saved visualization to {output_path}")


if __name__ == "__main__":
    main()
