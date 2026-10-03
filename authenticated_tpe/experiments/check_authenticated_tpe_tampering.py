"""Independent end-to-end tamper check, intentionally outside pytest tests."""
from __future__ import annotations

from pathlib import Path
import sys

import numpy as np
from PIL import Image

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
import authenticated_tpe as a


def main() -> None:
    image_path = PROJECT.parent / "tpe_rdh_reproduction" / "input" / "uct_colour" / "airplane.tif"
    image = np.asarray(Image.open(image_path).convert("RGB").resize((512, 512)), dtype=np.uint8)
    key = bytes(range(32))
    image_id = bytes(range(16))
    protected = a.protect_image(image, key, image_id)
    clean = a.verify_and_decrypt(protected.marked_image, key, image_id)
    assert clean.accepted and clean.mode == "group"
    assert np.array_equal(clean.recovered_image, image)

    modified = protected.marked_image.copy()
    modified[0, 0, 0] ^= 1
    tampered = a.verify_and_decrypt(modified, key, image_id)
    assert not tampered.accepted and tampered.recovered_image is None

    wrong_key = bytes([key[0] ^ 1]) + key[1:]
    wrong_key_result = a.verify_and_decrypt(protected.marked_image, wrong_key, image_id)
    assert not wrong_key_result.accepted and wrong_key_result.recovered_image is None

    wrong_id = bytes([image_id[0] ^ 1]) + image_id[1:]
    wrong_id_result = a.verify_and_decrypt(protected.marked_image, key, wrong_id)
    assert not wrong_id_result.accepted and wrong_id_result.recovered_image is None

    print("independent_clean_group_mode=PASS")
    print("independent_clean_exact_recovery=PASS")
    print(f"independent_single_bit_tamper_rejected={not tampered.accepted}")
    print(f"independent_failed_groups={len(tampered.failed_groups)}")
    print("independent_no_plaintext_on_tamper=PASS")
    print("independent_wrong_key_rejected=PASS")
    print("independent_wrong_image_id_rejected=PASS")


if __name__ == "__main__":
    main()
