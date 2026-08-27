"""Plot the Section 4 2D-CSM example sequences.

This experiment reproduces the paper's Section 4.2 trajectory setup:
`x0 = 0.3`, `y0 = 0.2`, `r1 = r2 = 50`, and 5000 iterations.

It plots:
- x_n over iteration index
- y_n over iteration index
- phase space `(x_n, y_n)`
"""

from pathlib import Path
import sys

import matplotlib.pyplot as plt


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from chaos import generate_2d_csm


def main() -> None:
    """Generate and save the Section 4.2-style 2D-CSM plots."""

    x0 = 0.3
    y0 = 0.2
    r1 = 50.0
    r2 = 50.0
    iterations = 5000

    x_values, y_values = generate_2d_csm(x0, y0, r1, r2, iterations)
    n_values = range(1, iterations + 1)

    fig, axes = plt.subplots(3, 1, figsize=(10, 12), constrained_layout=True)

    axes[0].plot(n_values, x_values, linewidth=0.8)
    axes[0].set_title("2D-CSM x_n sequence")
    axes[0].set_xlabel("Iteration n")
    axes[0].set_ylabel("x_n")

    axes[1].plot(n_values, y_values, linewidth=0.8, color="tab:orange")
    axes[1].set_title("2D-CSM y_n sequence")
    axes[1].set_xlabel("Iteration n")
    axes[1].set_ylabel("y_n")

    axes[2].scatter(x_values, y_values, s=2, alpha=0.5)
    axes[2].set_title("2D-CSM phase space")
    axes[2].set_xlabel("x_n")
    axes[2].set_ylabel("y_n")

    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "chaos_2d_csm.png"
    fig.savefig(output_path, dpi=200)
    print(f"Saved plot to {output_path}")


if __name__ == "__main__":
    main()

