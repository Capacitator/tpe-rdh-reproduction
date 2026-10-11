import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V2_SRC = ROOT.parent / "authenticated_tpe_nist_v2" / "src"
sys.path.insert(0, str(ROOT / "experiments"))
sys.path.insert(0, str(V2_SRC))

import atpe_v2 as v2
from run_r1_output_protocol import (
    BITS, BYTES, COUNT, KEY_BASE, KEYS_PER_STREAM, VALUES_PER_STREAM,
    build_stream, pool_key, set_two_bits,
)


def test_two_bit_packing_is_msb_first():
    b = bytearray(1)
    for i, value in enumerate((0, 1, 2, 3)):
        set_two_bits(b, i, value)
    assert b == b"\x1b"

    b = bytearray(1)
    for i, value in enumerate((3, 2, 1, 0)):
        set_two_bits(b, i, value)
    assert b == b"\xe4"


def test_actual_r1_matches_the_cipher_function():
    key = pool_key(KEY_BASE)
    kr1 = v2.derive_keys(key, 2)["Kr1"]
    assert v2.block_r1(kr1, 0) == int.from_bytes(
        __import__("hmac").new(kr1, b"r1\x00\x00", __import__("hashlib").sha256).digest()[:4], "big"
    ) % 4
    assert 0 <= v2.block_r1(kr1, 0) <= 3


def test_adjacent_stream_key_ranges_do_not_overlap():
    end_1 = KEY_BASE + KEYS_PER_STREAM - 1
    start_2 = KEY_BASE + KEYS_PER_STREAM
    assert end_1 < start_2
    assert KEY_BASE + (COUNT - 1) * KEYS_PER_STREAM + KEYS_PER_STREAM - 1 == 75_199


def test_generated_stream_is_exact_length_and_reproducible():
    stream1, meta1 = build_stream(1)
    stream2, meta2 = build_stream(1)
    assert len(stream1) == BYTES
    assert meta1["stream_bits"] == BITS
    assert meta1["r1_values"] == VALUES_PER_STREAM
    assert meta1["stream_sha256"] == meta2["stream_sha256"]
    assert stream1 == stream2


def test_last_index_has_its_own_disjoint_partition():
    _, first = build_stream(1)
    _, last = build_stream(COUNT)
    assert first["user_key_index_end_inclusive"] < last["user_key_index_start"]
    assert last["user_key_index_end_inclusive"] == 75_199
