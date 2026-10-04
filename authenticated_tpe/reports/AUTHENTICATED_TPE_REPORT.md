# Authenticated TPE: implementation and evaluation report

## Executive findings

This project is a separate prototype of the professor-supplied reversible block-group authentication method. It combines pair-sum-preserving two-pixel encryption, reversible contrast mapping (RCM), and HMAC-SHA256 tags. It is independently implemented and does not import the original chaotic TPE/RDH pipeline.

Checked-in outputs record 6/6 natural UCT clean cases with successful verification and exact recovery, and 7/7 controlled tampering or credential cases rejected without plaintext. A constructed capacity fixture exercises whole-image fallback. These observations cover the recorded cases and are not a formal security proof or independent cryptanalysis.

## Method and scope

The implementation follows the professor-provided *Reversible Block-Group Authentication for Thumbnail-Preserving Encrypted Color Images Using Reversible Contrast Mapping and HMAC-SHA256* (16 pages; SHA-256 `f0348a3435259037f53028830f4d00056f8ad58f4c87843f3766c924b1a1607d`). This is a documented reconstruction with explicit encoding conventions, not a run of the professor's Colab notebook.

Inputs are 512 × 512 RGB uint8 images, divided into 32 × 32 blocks. Each channel has 256 blocks, 512 adjacent horizontal pixel pairs per block, and 64 groups of four blocks. A full 256-bit HMAC-SHA256 tag is embedded per group, yielding 192 group tags across RGB. If any group cannot carry its tag, group marks are discarded and the implementation falls back to one whole-image tag.

The authentication hierarchy derives channel-specific TPE, block-shift and structure keys from the user key; group tags bind the private ImageID, channel and ordered block IDs, and a separate image tag binds the image ID. Group membership is generated deterministically from a key-derived HMAC_DRBG seed. The exact labels and encodings are specified in [`docs/AUTHENTICATED_TPE.md`](../docs/AUTHENTICATED_TPE.md). In production, the private ImageID is generated with the OS CSPRNG and retained by the owner. The API does not keep a registry to enforce uniqueness.

For each adjacent pair, Step 1 applies a key-derived reversible transform that preserves the pair sum. Step 2 cyclically shifts the smaller pixel value within each block using its derived `r1` value. HMAC_DRBG generates a key-dependent permutation of blocks, partitioned into groups of four. RCM embeds each group's full 256-bit HMAC-SHA256 tag; extraction reverses the mapping to recover and verify those tags. If any group cannot hold its tag, all provisional group marks are discarded and the code attempts one whole-image tag. Decryption/recovery is permitted only after the required tag verification succeeds; failed verification returns no plaintext. Exact encodings and RCM boundary conventions are documented in the method notes.

The six source fixtures are shared, read-only inputs at `../tpe_rdh_reproduction/input/uct_colour/`. The couple and girl source files are 256 × 256 and are resized to 512 × 512 by the experiment script; the other four are already 512 × 512. The experiment uses deterministic public test keys and IDs, which are not production secrets.

## Clean-image authentication results

| Image | Mode | Tags | Verified | Exact recovery | Pairs used | Marked vs Step-2 PSNR (dB) | Protect (s) | Verify (s) |
|---|---|---|---|---|---|---|---|---|
| airplane | group | 192 | True | True | 54314 | 30.200616 | 2.829163 | 3.179332 |
| baboon | group | 192 | True | True | 57326 | 27.708603 | 2.893875 | 3.142060 |
| couple | group | 192 | True | True | 80498 | 32.585125 | 2.998788 | 3.442145 |
| girl | group | 192 | True | True | 61936 | 30.054280 | 2.869511 | 3.300352 |
| lena | group | 192 | True | True | 54926 | 28.046331 | 2.826731 | 3.117933 |
| peppers | group | 192 | True | True | 57430 | 28.999219 | 2.875899 | 3.166885 |
| constructed_capacity_fallback_fixture | whole-image | 1 | True | True | 268 | 50.359641 | 2.417387 | 3.224808 |

The checked-in CSV contains 7 clean cases; 7/7 verify and recover exactly. These include the six UCT image cases; modes, tag counts, exact per-image values and timings above are read directly from `output/clean_authentication_results.csv`. Marked-image PSNR compares the marked image with the Step-2 image before RCM marking and is not a security metric.

## Tampering and authentication failures

| Attack | Rejected | Failed groups | Plaintext released |
|---|---|---|---|
| single_pixel_lsb_flip | True | 1 | False |
| same_channel_block_swap | True | 2 | False |
| cross_channel_block_swap | True | 2 | False |
| wrong_user_key | True | 0 | False |
| wrong_image_id | True | 0 | False |
| different_protected_image_replacement | True | 0 | False |
| single_pixel_lsb_flip_whole_image_mode | True | 0 | False |

The artifact records 7/7 attacks rejected and 7/7 with no plaintext released. Wrong-key, wrong-ImageID, replacement, same-channel block-swap, and cross-channel block-swap outcomes and failed-group counts are shown in the CSV-derived table. Group localization is only reported where verification identifies affected groups; zero means no failed group was attributable in these cases.

## Capacity and operating modes

| Fixture | Mode | Groups at target | Minimum group peak (bits) | Whole-image capacity (bits) |
|---|---|---|---|---|
| airplane | group | 192 | 1619 | 356142 |
| baboon | group | 192 | 1225 | 337798 |
| couple | group | 192 | 333 | 269366 |
| girl | group | 192 | 652 | 324672 |
| lena | group | 192 | 1392 | 353508 |
| peppers | group | 192 | 1216 | 338340 |
| constructed_capacity_fallback_fixture | whole-image | 189 | 0 | 368912 |

For the 6 group-mode natural-image cases, minimum group peak capacity ranges from 333 to 1619 bits; whole-image net capacity ranges from 269366 to 356142 bits. The separate constructed fixture exercises whole-image fallback: 189 groups meet the group threshold, and its whole-image capacity is 368912 bits. Capacity details are in `output/capacity_results.csv`.

## Tests, independent check, and provenance

Authenticated-project test command `python -m pytest tests -q` from `authenticated_tpe/` passed **19 passed in 45.42s**. The independent script `python experiments/check_authenticated_tpe_tampering.py` exited successfully; recorded output: `independent_clean_group_mode=PASS; independent_clean_exact_recovery=PASS; independent_single_bit_tamper_rejected=True; independent_failed_groups=1; independent_no_plaintext_on_tamper=PASS; independent_wrong_key_rejected=PASS; independent_wrong_image_id_rejected=PASS`.

### Artifact provenance

- Branch `authenticated-tpe-paper`; report source commit `ec2661b690fa544b32b4d785fca3da46dc5a9603`; worktree at report generation: `dirty`.
- Artifact-generating source commit: `e004bda185b10c5c0a91061e3715e8c3a0248f6b`; artifact source worktree state: `clean (recorded at run start, before regenerating output files)`.
- Runtime: Python 3.11.0; NumPy 2.4.4; Pillow 12.0.0; pytest 8.4.2.
- Input paths: `../tpe_rdh_reproduction/input/uct_colour/{airplane,baboon,couple,girl,lena,peppers}.tif` (read-only shared UCT fixtures).
- Input image SHA-256 values:

  - `airplane.tif`: `515d0a5105047916be9faed513330046be41a61f4b155e854731e512ce1f4c4a`
  - `baboon.tif`: `cd4456f2562dc352acee627428eb4e2ccaed5f53082ce0838d9fff6b8a3e3517`
  - `couple.tif`: `e1760e29f10762fe60349e2848b01065b69784d04848606dd8644b6a9a893288`
  - `girl.tif`: `d044fcfbea02123efdc167e596f45e839c39c2e1ca2ff841710ef4db15bc4dfb`
  - `lena.tif`: `d5cd280e7e970a31828fe2c91ead6c8ce3ea257d04b6eabbd8e254c6e1cce255`
  - `peppers.tif`: `208e8c6542e91a1b3d7d9457626b7577fc0d21affeb800435858cc83f2537649`
- Specification SHA-256: `f0348a3435259037f53028830f4d00056f8ad58f4c87843f3766c924b1a1607d`.
- Public deterministic test fixtures only; no secret key or private production ImageID is reproduced here.
- Report-generation script: `authenticated_tpe/experiments/generate_authenticated_report.py`; exact command: `.venv/bin/python authenticated_tpe/experiments/generate_authenticated_report.py` from repository root.
- Source/artifact paths: `authenticated_tpe/src/`, `tests/`, `experiments/`, `docs/`, and `output/`; measurements are from `output/clean_authentication_results.csv`, `tamper_results.csv`, `capacity_results.csv`, and `provenance.txt`.

## Reproduction status and limitations

The implementation reconstructs the paper description using explicit documented conventions. Not reproduced: required original notebook/data/parameter was unavailable. The reported six UCT fixtures, constructed fallback fixture, and finite attack set are prototype evaluation, not a formal security proof or independent cryptanalysis. No authenticated-project NIST SP 800-22 or NPCR/UACI result is claimed. Lossless image handling, UserKey secrecy, and fresh private production ImageIDs remain operational requirements.

## Reproduction

From the repository root:

```bash
.venv/bin/python -m pytest authenticated_tpe/tests -q
.venv/bin/python authenticated_tpe/experiments/run_authenticated_tpe.py
.venv/bin/python authenticated_tpe/experiments/check_authenticated_tpe_tampering.py
```

## Artifact map

- Method notes: [`docs/AUTHENTICATED_TPE.md`](../docs/AUTHENTICATED_TPE.md)
- Raw clean-image results: [`output/clean_authentication_results.csv`](../output/clean_authentication_results.csv)
- Tampering results: [`output/tamper_results.csv`](../output/tamper_results.csv)
- Capacity results: [`output/capacity_results.csv`](../output/capacity_results.csv)
- Key derivation vectors: [`output/key_derivation_vectors.txt`](../output/key_derivation_vectors.txt)
- Run provenance: [`output/provenance.txt`](../output/provenance.txt)
- Original chaotic reproduction report: [`../../tpe_rdh_reproduction/reports/ORIGINAL_TPE_RDH_REPORT.md`](../../tpe_rdh_reproduction/reports/ORIGINAL_TPE_RDH_REPORT.md)
- Cross-project comparison: [`../../reports/COMPARISON.md`](../../reports/COMPARISON.md)
