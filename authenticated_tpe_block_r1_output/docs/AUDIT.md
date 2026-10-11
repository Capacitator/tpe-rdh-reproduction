# Block-r1 NIST input-selection correction

## Finding

The existing `block_r1` category in `authenticated_tpe_nist_v2` feeds full 32-byte HMAC-SHA256 digests into NIST STS. That is a useful test of the underlying HMAC PRF outputs, but it is not literally the sequence consumed by the encryption transform. The cipher's `block_r1` function consumes only `int.from_bytes(digest[:4], 'big') % 4`, a value in `0..3` (two bits).

This supplemental campaign tests those actual consumed `r1` symbols. It does **not** replace, edit, or relabel the old full-digest results. This addresses input selection; it is not a code change intended to improve the p-values.

## Construction

For each of 100 streams, enumerate the real function's outputs in channel order 0,1,2 and block order 0..255. Each key supplies 768 two-bit symbols. Use enough distinct predetermined UserKeys to obtain 500,000 symbols (=1,000,000 bits), requiring 652 UserKeys per stream, with the final key truncated at the predefined length. Key indices use the same deterministic domain-separated recipe as the primary campaign:

`UserKey_i = SHA-256(b"atpe-v2|userkey|" || u32be(i))`

The new index range 10,000..75,199 is disjoint from every index in the original protocol. No key is reused across these supplemental streams. No p-value, image identifier or existing stream was selected or changed.

The 2-bit symbols are packed in their natural numeric order, most-significant symbol first within each byte. For symbols `[0,1,2,3]`, the packed byte is `00 01 10 11` (`0x1b`). Each stream is exactly 125,000 bytes / 1,000,000 bits. The official NIST STS 2.1.2 `assess` binary, ASCII input mode, all tests and default parameters are used; first-level α is 0.01 and NIST second-level uniformity uses 0.0001.

## Interpretation

These data answer a different and more direct question than the existing raw-digest category: whether the *derived two-bit values actually used as r1* have detectable structure. NIST tests do not prove cryptographic security. All results, including p-values below α and N/A outcomes, are retained. The previous full-digest campaign remains intact for comparison.

## Reproduction

```bash
python3 experiments/run_r1_output_protocol.py --sts-dir /path/to/sts-2.1.2
python3 -m pytest tests -q
```

The script writes the streams, manifests, full first-level and second-level CSVs, original STS reports, parse warnings, summary and provenance under `output/`.
