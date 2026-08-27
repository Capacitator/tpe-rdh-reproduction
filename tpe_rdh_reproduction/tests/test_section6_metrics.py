from pathlib import Path
import sys

import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "experiments"))

from run_section6_experiments import (
    make_differential_plaintext,
    npcr_uaci_channel,
    npcr_uaci_rows,
)


def test_make_differential_plaintext_changes_one_selected_channel_pixel_per_block():
    image = np.zeros((8, 8, 3), dtype=np.uint8)

    modified = make_differential_plaintext(image, block_size=4, channel=0)

    changed = image != modified
    assert changed[:, :, 0].sum() == 4
    assert changed[:, :, 1].sum() == 0
    assert changed[:, :, 2].sum() == 0
    assert modified[0, 0, 0] == 1
    assert modified[0, 4, 0] == 1
    assert modified[4, 0, 0] == 1
    assert modified[4, 4, 0] == 1


def test_npcr_uaci_channel_match_paper_equations_15_to_17():
    cipher_a = np.zeros((2, 2, 3), dtype=np.uint8)
    cipher_b = cipher_a.copy()
    cipher_b[0, 0, 0] = 255
    cipher_b[1, 1, 0] = 128

    npcr, uaci = npcr_uaci_channel(cipher_a, cipher_b, channel=0)

    assert npcr == 50.0
    assert uaci == ((255 + 128) / (255 * 4)) * 100.0


def test_npcr_uaci_channel_uses_requested_channel_only():
    cipher_a = np.zeros((2, 2, 3), dtype=np.uint8)
    cipher_b = cipher_a.copy()
    cipher_b[0, 0, 1] = 255

    red_npcr, red_uaci = npcr_uaci_channel(cipher_a, cipher_b, channel=0)
    green_npcr, green_uaci = npcr_uaci_channel(cipher_a, cipher_b, channel=1)

    assert red_npcr == 0.0
    assert red_uaci == 0.0
    assert green_npcr == 25.0
    assert green_uaci == 25.0


def test_npcr_uaci_rows_include_rgb_channels_and_mean():
    cipher_a = np.zeros((2, 2, 3), dtype=np.uint8)
    cipher_b = cipher_a.copy()
    cipher_b[0, 0, 0] = 255

    rows = npcr_uaci_rows("img", 4, cipher_a, cipher_b)

    assert [row["channel"] for row in rows] == ["R", "G", "B", "RGB_mean"]
    assert rows[0]["npcr_percent"] == 25.0
    assert rows[1]["npcr_percent"] == 0.0
    assert rows[2]["npcr_percent"] == 0.0
    assert rows[3]["npcr_percent"] == 25.0 / 3.0
