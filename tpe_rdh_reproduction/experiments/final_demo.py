"""Create one clean demonstration of the current working implementation.

This script does not modify the encryption algorithm. It runs the existing
pipeline on one real 512x512 RGB image and saves each major stage:

1. original
2. permutation output
3. RDH marked output
4. final encrypted image
5. recovered image
6. extracted payload
"""

from __future__ import annotations

from pathlib import Path
import sys

import matplotlib.pyplot as plt
import numpy as np
from PIL import Image
from skimage import data, transform


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from pipeline import DemoPipelineParameters, decrypt_rgb_image, encrypt_rgb_image
from rdh import bits_from_bytes, bytes_from_bits


def load_demo_image() -> np.ndarray:
    """Load one real RGB image and resize it to the paper-style 512x512 size."""

    image = data.coffee()
    image = transform.resize(
        image,
        (512, 512),
        order=1,
        preserve_range=True,
        anti_aliasing=True,
    )
    return np.rint(image).clip(0, 255).astype(np.uint8)


def save_rgb(path: Path, image: np.ndarray) -> None:
    """Save an RGB uint8 array as PNG."""

    Image.fromarray(image, mode="RGB").save(path)


def main() -> None:
    """Run the current end-to-end implementation and save final demo artifacts."""

    output_dir = PROJECT_ROOT / "output" / "final_demo"
    output_dir.mkdir(parents=True, exist_ok=True)

    params = DemoPipelineParameters(block_size=16)
    payload = b"Current TPE-RDH reproduction demo payload"
    payload_bits = bits_from_bytes(payload)

    original = load_demo_image()
    encrypted = encrypt_rgb_image(original, payload_bits, params)
    decrypted = decrypt_rgb_image(encrypted.encrypted_image, params)
    extracted_payload = bytes_from_bits(decrypted.payload_bits)

    max_recovery_error = int(
        np.abs(original.astype(np.int16) - decrypted.recovered_image.astype(np.int16)).max()
    )
    exact_recovery = bool(np.array_equal(original, decrypted.recovered_image))
    payload_recovered = extracted_payload == payload

    save_rgb(output_dir / "01_original.png", original)
    save_rgb(output_dir / "02_permutation_output.png", encrypted.permuted_image)
    save_rgb(output_dir / "03_rdh_marked_output.png", encrypted.marked_image)
    save_rgb(output_dir / "04_final_encrypted.png", encrypted.encrypted_image)
    save_rgb(output_dir / "05_recovered.png", decrypted.recovered_image)
    (output_dir / "06_extracted_payload.txt").write_text(
        extracted_payload.decode("utf-8"), encoding="utf-8"
    )

    stages = [
        ("Original", original),
        ("Permutation", encrypted.permuted_image),
        ("RDH marked", encrypted.marked_image),
        ("Final encrypted", encrypted.encrypted_image),
        ("Recovered", decrypted.recovered_image),
    ]
    fig, axes = plt.subplots(1, len(stages), figsize=(15, 3.2), constrained_layout=True)
    for axis, (title, image) in zip(axes, stages):
        axis.imshow(image)
        axis.set_title(title)
        axis.set_xticks([])
        axis.set_yticks([])
    fig.savefig(output_dir / "final_demo_stages.png", dpi=200)

    report = f"""Final demonstration report

Image used: skimage.data.coffee resized to 512x512 RGB
Exact recovery: {'yes' if exact_recovery else 'no'}
Max recovery error: {max_recovery_error}
Payload recovered: {'yes' if payload_recovered else 'no'}
Block size: {params.block_size}
vartheta: {params.vartheta}

Implementation assumptions:
- Implementation decision: the 256-bit key is converted to x0, y0, r1, r2, and kappa_1 by the documented convention in src/chaos.py.
- Implementation decision: image identifier T is converted to T_tau, then kappa_2 is derived with the documented two-stage Section 5.1 procedure.
- Paper ambiguity / implementation decision: vartheta=10000.0 is inferred from Fig. 4 examples, not explicit text.
- Paper ambiguity / implementation decision: permutation uses row-major flattening and stable ascending sort of Upsilon_P blocks.
- Paper ambiguity / implementation decision: substitution pairs pixels and Upsilon_S values in row-major flattened order.
- Paper ambiguity / implementation decision: RDH uses an explicit metadata header because the paper does not define payload/overhead serialization.
- Paper ambiguity / implementation decision: first 16 top-row pixels are excluded from RDH histogram shifting and embedding.
- Paper ambiguity / implementation decision: RGB payload is embedded in channel 0 only; channels 1 and 2 receive empty RDH payloads.
"""
    (output_dir / "final_demo_report.txt").write_text(report, encoding="utf-8")

    print(report)
    print(f"Saved final demo artifacts to {output_dir}")


if __name__ == "__main__":
    main()
