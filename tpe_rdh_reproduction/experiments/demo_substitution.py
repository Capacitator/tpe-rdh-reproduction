"""Small Section 5.4 substitution demo.

This script demonstrates only substitution encryption and inverse substitution
on one grayscale/channel image. It does not run permutation, RDH, or the full
pipeline.

PAPER AMBIGUITY / IMPLEMENTATION DECISION:
The text only states `vartheta >> 1`. `DEMO_VARTETHA=10000.0` is an inference
from Fig. 4 examples such as `0.7492 -> 7492`, not an explicit textual value.
"""

from pathlib import Path
import sys

import matplotlib.pyplot as plt
import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from chaos import generate_upsilon_matrices
from substitution import (
    chaotic_pair_delta,
    encrypt_pair,
    index_to_pair,
    inverse_substitute_channel_blocks,
    pair_to_index,
    same_sum_pair_count,
    substitute_channel_blocks,
)


DEMO_VARTETHA = 10000.0
DEMO_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
    "102132435465768798a9babbdcedfe0f"
)
DEMO_IDENTIFIER = b"demo-substitution-image"


def _make_demo_channel() -> np.ndarray:
    rows, cols = np.indices((8, 8))
    return ((rows * 24 + cols * 9) % 256).astype(np.uint8)


def main() -> None:
    """Run a tiny Section 5.4 substitution demonstration."""

    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    channel = _make_demo_channel()
    _, upsilon_s = generate_upsilon_matrices(8, 8, DEMO_KEY, DEMO_IDENTIFIER)

    encrypted = substitute_channel_blocks(channel, upsilon_s, 4, DEMO_VARTETHA)
    recovered = inverse_substitute_channel_blocks(encrypted, upsilon_s, 4, DEMO_VARTETHA)

    np.save(output_dir / "demo_substitution_original.npy", channel)
    np.save(output_dir / "demo_substitution_encrypted.npy", encrypted)
    np.save(output_dir / "demo_substitution_recovered.npy", recovered)

    fig, axes = plt.subplots(1, 3, figsize=(9, 3), constrained_layout=True)
    axes[0].imshow(channel, cmap="gray", vmin=0, vmax=255)
    axes[0].set_title("Input channel")
    axes[1].imshow(encrypted, cmap="gray", vmin=0, vmax=255)
    axes[1].set_title("Substituted")
    axes[2].imshow(recovered, cmap="gray", vmin=0, vmax=255)
    axes[2].set_title("Recovered")
    for axis in axes:
        axis.set_xticks([])
        axis.set_yticks([])

    output_path = output_dir / "demo_substitution.png"
    fig.savefig(output_path, dpi=200)

    tau1, tau2 = 40, 70
    gamma1, gamma2 = 0.2, 0.4
    eta = pair_to_index(tau1, tau2)
    delta = chaotic_pair_delta(gamma1, gamma2, DEMO_VARTETHA)
    count = same_sum_pair_count(tau1 + tau2)
    eta_e = (eta + delta) % count
    encrypted_pair = index_to_pair(eta_e, tau1 + tau2)

    print("PAPER AMBIGUITY: DEMO_VARTETHA=10000.0 is inferred from Fig. 4, not explicit text.")
    print("PAPER AMBIGUITY: row-major pair order is documented in src/substitution.py.")
    print(f"Recovered exactly: {np.array_equal(channel, recovered)}")
    print(
        "Example: "
        f"({tau1}, {tau2}) -> eta={eta} -> delta={delta} -> "
        f"eta_e={eta_e} -> encrypted_pair={encrypted_pair}"
    )
    print(f"Saved demo visualization to {output_path}")


if __name__ == "__main__":
    main()
