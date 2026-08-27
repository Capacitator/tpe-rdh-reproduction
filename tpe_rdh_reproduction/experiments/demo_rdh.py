"""Small Section 5.3 grayscale RDH demo.

This script demonstrates only information embedding/extraction and exact
carrier recovery for one grayscale/channel image. It does not run substitution
or the full encryption pipeline.
"""

from pathlib import Path
import sys

import matplotlib.pyplot as plt
import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from rdh import bits_from_bytes, bytes_from_bits, embed_bits, extract_bits_and_recover


def _make_demo_channel() -> np.ndarray:
    channel = np.full((32, 32), 90, dtype=np.uint8)
    channel[0, :16] = np.arange(16, dtype=np.uint8)
    channel[1:8, 1:8] = 89
    channel[16:24, 16:24] = 160
    channel[2, 20] = 0
    channel[3, 20] = 255
    return channel


def main() -> None:
    """Embed a short payload, extract it, and save visual checks."""

    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    original = _make_demo_channel()
    payload_bits = bits_from_bytes(b"Section 5.3 RDH")

    marked, info = embed_bits(original, payload_bits)
    extracted_bits, recovered = extract_bits_and_recover(marked)

    np.save(output_dir / "demo_rdh_original.npy", original)
    np.save(output_dir / "demo_rdh_marked.npy", marked)
    np.save(output_dir / "demo_rdh_recovered.npy", recovered)

    fig, axes = plt.subplots(2, 3, figsize=(10, 6), constrained_layout=True)
    axes[0, 0].imshow(original, cmap="gray", vmin=0, vmax=255)
    axes[0, 0].set_title("Original channel")
    axes[0, 1].imshow(marked, cmap="gray", vmin=0, vmax=255)
    axes[0, 1].set_title("Marked channel")
    axes[0, 2].imshow(recovered, cmap="gray", vmin=0, vmax=255)
    axes[0, 2].set_title("Recovered channel")

    axes[1, 0].hist(original.reshape(-1), bins=256, range=(0, 255))
    axes[1, 0].set_title("Original histogram")
    axes[1, 1].hist(marked.reshape(-1), bins=256, range=(0, 255))
    axes[1, 1].set_title("Marked histogram")
    axes[1, 2].imshow(np.abs(marked.astype(int) - original.astype(int)), cmap="magma")
    axes[1, 2].set_title("|Marked - Original|")

    for axis in axes[0]:
        axis.set_xticks([])
        axis.set_yticks([])

    output_path = output_dir / "demo_rdh.png"
    fig.savefig(output_path, dpi=200)

    print(f"P={info.peak}, Z={info.zero}, embedded bits={info.embedded_bit_count}")
    print(f"Extracted payload: {bytes_from_bits(extracted_bits)!r}")
    print(f"Recovered exactly: {np.array_equal(original, recovered)}")
    print(f"Saved demo visualization to {output_path}")


if __name__ == "__main__":
    main()
