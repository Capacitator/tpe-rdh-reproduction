# Reversible block-group authentication prototype: experiment report

The evaluation uses six public UCT images because the eight CelebA-HQ source files were unavailable. Authenticated-TPE is implemented with a fixed 32×32 block size; authenticated 8×8 and 16×16 results are therefore not reported.

## Scope and source

This report documents the separate prototype in `src/authenticated_tpe.py`; it does not replace or alter the existing chaotic TPE/RDH reproduction. The method was reconstructed from the professor-supplied *Reversible Block-Group Authentication for Thumbnail-Preserving Encrypted Color Images Using Reversible Contrast Mapping and HMAC-SHA256* (16-page PDF; Sections 1–10). These are our implementation results, not the PDF's Colab/reference notebook results.

The prototype enforces 512 x 512 RGB uint8 images, 32 x 32 non-overlapping blocks, 256 blocks per channel, 512 horizontal raster-order pairs per block, four ordered blocks per group, 64 groups per channel, and full 256-bit HMAC-SHA256 tags. The test-only key is `bytes(range(32))`; test ImageIDs are deterministic SHA-256 fixtures. Neither is suitable for production.

The key hierarchy is `Kch,c = HMAC(UserKey, b'channel'||c)`, `Ktpe,c = HMAC(Kch,c,b'tpe')`, `Kr1,c = HMAC(Kch,c,b'r1')`, `Kstruct,c = HMAC(Kch,c,b'struct')`, `Kauth = HMAC(UserKey,b'auth')`, `Kgroup = HMAC(Kauth,ImageID||c||Bid0||Bid1||Bid2||Bid3)`, and `Kimage = HMAC(Kauth,b'image'||ImageID)`. Exact fixed-width encodings and domain labels are documented in `docs/AUTHENTICATED_TPE.md`.

## Clean-image results

Fresh six-image authenticated-TPE clean run, generated at source commit `08b16e6c03c84f3bf5b3175c1648413bc38d461f` with public deterministic fixtures. The exact eight CelebA-HQ images are unavailable; these six UCT rows are an adapted experiment. Block size is fixed at 32×32; authenticated 8×8/16×16 results are unavailable. Protection and verification times exclude file I/O. Marked-vs-Step-2 quality metrics compare the RCM-marked output with the actual Step-2 image, and do not measure security.

| Image | Mode | Tags | Verified | Exact recovery | Pairs used | Marked-vs-Step-2 PSNR (dB) | Protect (s) | Verify (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| airplane | group | 192 | True | True | 54422 | 30.197769 | 1.801782667 | 1.982827250 |
| baboon | group | 192 | True | True | 57474 | 27.771427 | 1.794341667 | 1.992045625 |
| couple | group | 192 | True | True | 80778 | 32.624797 | 1.891289376 | 2.164496500 |
| girl | group | 192 | True | True | 62248 | 30.107185 | 1.798324209 | 2.004182667 |
| lena | group | 192 | True | True | 55012 | 28.060002 | 1.765184042 | 1.952447917 |
| peppers | group | 192 | True | True | 57422 | 29.030458 | 1.794741292 | 1.979297791 |
| constructed_capacity_fallback_fixture (separate) | whole-image | 1 | True | True | 268 | 50.359641 | 2.417387 | 3.224808 |

The machine-readable six-image metrics and raw RGB SHA-256 values are in `output/experimental_results_template/clean_results.csv`. All six natural images authenticate and recover exactly. The constructed fallback fixture is separate from the six-image population.

## Authentication and tamper checks

| Attack | Rejected | Failed groups reported | Plaintext released |
|---|---:|---:|---:|
| single_pixel_lsb_flip | True | 1 | False |
| same_channel_block_swap | True | 2 | False |
| cross_channel_block_swap | True | 2 | False |
| wrong_user_key | True | 0 | False |
| wrong_image_id | True | 0 | False |
| different_protected_image_replacement | True | 0 | False |
| single_pixel_lsb_flip_whole_image_mode | True | 0 | False |

Observed controlled attack cases rejected: 7/7; observed false acceptances: 0. This finite test count is not a statistical proof or a security bound. Group-mode edits localized to 1, 2, 2 affected groups for the single-pixel, same-channel swap, and cross-channel swap cases respectively. Whole-image fallback reports no authenticated location. Wrong UserKey, wrong ImageID, and another protected file under the same UserKey were rejected. Failed verification returns no recovered image.

A separate script outside pytest (`experiments/check_authenticated_tpe_tampering.py`) independently confirmed clean group verification and exact recovery, one-bit tamper rejection with a failed group identified, and wrong-key/wrong-ImageID rejection. Lossless PNG save/reload is checked by a pytest integration test. JPEG/recompression behavior and the PDF's full attack study have not been reproduced.

## Capacity and operating mode

Capacity is the prefix net `A - N` in the required traversal (usable T/O pairs add one; N pairs subtract one). Group mode is all-or-nothing: every group must reach 256 net bits. When any group fails, provisional group marks are discarded and one 256-bit whole-image tag is embedded instead. See `capacity_results.csv` for measured per-group peak net capacities and whole-image totals. In the constructed fallback fixture 3 of 192 groups were below 256 bits, while whole-image capacity was sufficient.

RCM overflow/underflow is prevented by restricting transformable T pairs to `D_c`, where both forward coordinates are in [0,255] and the ambiguous odd border pairs are removed. O pairs use the specified odd-pair representation; N pairs are not transformed and their first-pixel LSB is saved and restored. If an image/group cannot reach 256 net bits, group marks are abandoned for whole-image fallback; if the whole image also lacks capacity, `InsufficientCapacity` rejects it without returning a marked result.

## Reproduction and provenance

```bash
../.venv/bin/python -m pytest tests -q
../.venv/bin/python experiments/run_authenticated_tpe.py
../.venv/bin/python experiments/check_authenticated_tpe_tampering.py
```

Source commit: `e004bda185b10c5c0a91061e3715e8c3a0248f6b`. Worktree at run start: `clean`. The experiment reads the shared UCT images from `../tpe_rdh_reproduction/input/uct_colour/`. Python, NumPy, Pillow, source hashes, deterministic fixture rules, and the exact generation command are in `provenance.txt`.

## Sources and limitations

Primary method specification: the professor-supplied *Our method.pdf*, Sections 1–10 (SHA-256 `f0348a3435259037f53028830f4d00056f8ad58f4c87843f3766c924b1a1607d`). The method document cites Coltuc and Chassery (2007) for reversible contrast mapping, [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) for HMAC, [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) for SHA-256, and [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) for HMAC_DRBG. NIST's [CAVP RNG page](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Random-Number-Generators) provides DRBG test vectors for informal checking and states these do not replace CAVP validation. The checked-in DRBG regression uses the professor PDF's exact permutation prefix and a separately calculated full permutation digest; this project did not claim CAVP validation or import NIST's vector archive. This reproduction uses the exact deterministic conventions listed in `docs/AUTHENTICATED_TPE.md` and the known-answer vectors in `key_derivation_vectors.txt`.

The implementation is a research prototype, not a claim of cryptographic security. Authentication depends on secrecy and handling of UserKey and a fresh private ImageID, exact lossless pixel preservation, and implementation correctness. ImageID uniqueness is an owner responsibility; the API has no persistent reuse registry. Step 1 preserves adjacent pair sums and leaks them by design, and Step 2's four-value per-block shift is not relied on for confidentiality. No independent cryptanalysis or formal proof was performed. RCM/HMAC tests, exact recovery, and these controlled attack checks do not prove overall security. Group authentication identifies an affected group of four scattered blocks, not the exact altered block; whole-image mode only returns an image-level result.
