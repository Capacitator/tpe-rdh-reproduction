# Original Chaotic TPE/RDH Reproduction Report

## Paper and scope

**Paper:** An, D., Pu, X., Lu, J., and Xia, X., “A dual-mode thumbnail-preserving encryption scheme based on chaotic system and reversible data hiding,” *Journal of King Saud University Computer and Information Sciences* (2026), [doi:10.1007/s44443-026-00479-y](https://doi.org/10.1007/s44443-026-00479-y).

This report covers only the original chaotic TPE/RDH implementation in this project. It summarizes the project’s implementation and validation artifacts; it does not claim to reproduce the authors’ complete experimental tables. The original paper uses the Helen dataset. This project’s image validation uses six UCT color images, four `skimage.data` images, and a deterministic synthetic demo, depending on the experiment.

## Implementation

The RGB pipeline in `src/pipeline.py` follows the paper’s encryption order:

1. Derive image- and key-dependent chaotic state and generate `Upsilon_P` and `Upsilon_S` (`src/chaos.py`).
2. Permute pixel positions independently inside corresponding `b × b` blocks, controlled by sorted `Upsilon_P` values (`src/permutation.py`).
3. Embed payload and recovery metadata in each channel by histogram-shifting reversible data hiding (RDH; `src/rdh.py`).
4. Apply sum-preserving two-pixel substitution controlled by `Upsilon_S` (`src/substitution.py`).

Decryption reverses substitution, extracts the payload and restores the RDH carrier, then inverse-permutes the channels. `decrypt_rgb_image` returns the recovered image and payload bits. The implementation checks exact equality in its tests and reports PSNR/SSIM where applicable.

### Chaotic maps and matrix generation

`src/chaos.py` implements the cubic and sinusoidal maps, the coupled two-dimensional CSM update, and the two-stage iteration used to produce `Upsilon_P` and `Upsilon_S`. `Upsilon_P` drives block permutation; `Upsilon_S` drives the substitution offset. The NIST stream experiment quantizes these matrices with `floor((x+1)*128)`, clips to `uint8`, concatenates P then S, and serializes row-major.

The paper does not fully define the byte-level 256-bit key conversion, initial parameters, `T`/`T_tau` conversion, or `kappa_2`. The implementation splits a 32-byte key into four 64-bit fields for `x0`, `y0`, `r1`, and `r2`; derives `kappa_1` and the positive bounded `T_tau`/`kappa_2` values with domain-separated SHA-256 conventions; and binds the complete image identifier and first-stage state into `kappa_2`. These are documented implementation choices, not paper-specified constants.

### Permutation, RDH, and substitution

Permutation uses row-major flattening and stable ascending sort within each block. RDH finds histogram peak/zero points, records overhead where a true zero must be created, stores peak/zero metadata, and embeds the user payload. The RGB payload is split into channel chunks because the paper does not define its exact RGB metadata format.

Substitution maps each pixel pair to its index among pairs with the same sum, adds a chaotic offset modulo the size of that same-sum class, and maps the index back to a pair. Thus substitution preserves the block sums of the RDH-marked image. RDH itself can change those sums; the project does not claim that the final block sums always equal the unmarked source image.

### Image-derived key-reuse behavior

When no identifier is provided, the pipeline derives `T` from the plaintext RGB image bytes using the documented image-identifier convention. The resolved identifier must be retained for decryption. The fixed-key UCT experiment records different identifiers, `Upsilon_P`/`Upsilon_S` hashes, and ciphertext hashes for airplane and baboon; the final demo separately reports the same-key/different-image check passing. This tests the implementation’s diversification behavior. It is not evidence of cryptographic security.

## Validation results

### Exact recovery, payload, and capacity

`output/uct_colour_all_blocks/summary.csv` contains 24 UCT image/block-size runs (six images × block sizes 8, 16, 32, and 64). All 24 report exact recovery, zero maximum recovery error, payload recovery, and post-RDH block-sum preservation. The original images retain their native dimensions there: airplane, baboon, lena, and peppers are 512×512; couple and girl are 256×256.

The Section 6-style experiment uses `coffee`, `chelsea`, `rocket`, and `hubble_deep_field` from `skimage.data`, with 512×512 preprocessing, block sizes 8, 16, 32, and 64, and a 64-bit payload. All 16 runs report exact recovery (`PSNR=inf`, `SSIM=1`, maximum error 0). The synthetic demonstration (`results/metrics.txt`) also reports exact recovery and recovery of its 248-bit payload.

### Thumbnail and block sums

The UCT all-block results report preserved post-RDH block sums in all 24 runs. The separate `output/thumbnail_metrics.csv` demo measures stages independently: in that artifact, RDH changed 40 of 255 block/channel sums (maximum absolute difference 10), while substitution changed none (255/255 exact). That is the expected distinction: substitution preserves the sums presented to it, which are the RDH-marked sums.

### NPCR and UACI

The Section 6 differential experiment alters the top-left pixel of every block by +1 (or −1 at 255) in the R channel, then lets the default pipeline derive an image identifier from each plaintext. Across its 16 image/block-size RGB-mean rows, NPCR ranges from **96.93% to 99.50%** and UACI from **6.30% to 26.60%**. Across the per-channel rows, NPCR ranges from **96.66% to 99.55%** and UACI from **6.15% to 28.55%**. These values reflect both plaintext changes and identifier-dependent chaotic state; the source experiment explicitly treats them as validation metrics, not a faithful reproduction of the paper’s underspecified differential test.

The separate one-bit-key sweep (`output/key_sensitivity/uct_key_sensitivity_npcr_uaci.csv`) covers six UCT images and block sizes 8, 16, 32, and 64, holding the image identifier fixed. Its RGB NPCR range is **95.93%–99.47%**, with RGB UACI **9.70%–27.35%**. Per-channel values are retained in the CSV.

### Entropy and adjacent-pixel correlation

The checked-in numerical entropy result is from the deterministic synthetic 512×512 RGB demo only: entropy is **3.8154 bits** for the source and **7.9874 bits** for the final encrypted image, using that report’s image-level histogram calculation. No all-image, per-channel entropy table is present in the original project outputs, so these two values must not be generalized to the UCT or `skimage` sets.

The Section 6 correlation CSV uses 5,000 deterministically sampled adjacent pairs per direction after RGB-to-luminance conversion (not separate R/G/B correlations). Across the four `skimage.data` images and four block sizes, original luminance correlations range from **0.7573 to 0.9905** and encrypted luminance correlations from **−0.2054 to 0.6929**. The synthetic demo reports its own horizontal, vertical, and diagonal values in `results/metrics.txt`; those are a separate fixture and run.

## NIST SP 800-22 Rev. 1a

`experiments/run_nist_sp800_22.py` drives the official NIST STS 2.1.2 `assess` program. It tests two source categories: quantized `Upsilon_P` followed by `Upsilon_S`, and final encrypted RGB bytes. Each category has 10 streams of 1,000,000 bits, MSB-first, truncated after row-major serialization. The stream image order is airplane, baboon, couple, girl, lena, peppers, airplane, baboon, couple, girl. Streams 1 and 2 share a fixed key; streams 3–10 use distinct fixed fixtures. The pipeline derives image identifiers from plaintext.

The test uses alpha 0.01. Parameters recorded in provenance include Block Frequency M=128; non-overlapping and overlapping template m=9; approximate entropy m=10; serial m=16; linear complexity M=500; other settings use STS 2.1.2 defaults. `results.csv` contains every per-stream/component p-value and pass/fail/not-applicable value. Aggregate row counts are:

| Stream category | Pass | Fail | Not applicable | Total component outcomes |
|---|---:|---:|---:|---:|
| Chaotic matrices | 484 | 1,292 | 104 | 1,880 |
| Final ciphertext | 410 | 1,210 | 260 | 1,880 |

Per-test outcomes from `output/nist_sp800_22/results.csv`:

| Test | Chaotic pass / fail / N/A | Ciphertext pass / fail / N/A |
|---|---:|---:|
| Frequency | 8 / 2 / 0 | 0 / 10 / 0 |
| Block Frequency | 0 / 10 / 0 | 0 / 10 / 0 |
| Cumulative Sums | 16 / 4 / 0 | 0 / 20 / 0 |
| Runs | 0 / 10 / 0 | 0 / 10 / 0 |
| Longest Run | 0 / 10 / 0 | 2 / 8 / 0 |
| Rank | 10 / 0 / 0 | 3 / 7 / 0 |
| FFT | 0 / 10 / 0 | 0 / 10 / 0 |
| Non-overlapping Template | 325 / 1,155 / 0 | 389 / 1,091 / 0 |
| Overlapping Template | 0 / 10 / 0 | 2 / 8 / 0 |
| Universal | 0 / 10 / 0 | 0 / 10 / 0 |
| Approximate Entropy | 0 / 10 / 0 | 0 / 10 / 0 |
| Random Excursions | 7 / 41 / 32 | 0 / 0 / 80 |
| Random Excursions Variant | 108 / 0 / 72 | 0 / 0 / 180 |
| Serial | 0 / 20 / 0 | 4 / 16 / 0 |
| Linear Complexity | 10 / 0 / 0 | 10 / 0 / 0 |

The outcomes are mixed and include substantial failures. “Not applicable” means STS did not apply that component to a stream, not a pass. No algorithm parameters were tuned to improve these outcomes. NIST statistical tests do not establish cryptographic security and are not a substitute for cryptanalysis.

## Assumptions and limitations

- Several paper details are underspecified: key-to-chaos conversion, the matrix-generation interpretation, sorting/tie behavior, block/pair order, `vartheta`, RGB payload/metadata layout, no-zero overhead encoding, and the exact Section 6.8 plaintext-change protocol. See `docs/paper_map.md`, `docs/IMPLEMENTATION_NOTES.md`, and `docs/SECTION5_NOTES.md`.
- The primary validation images differ from the paper’s Helen dataset. The `skimage.data` Section 6 results, UCT results, synthetic demo, key sensitivity sweep, and NIST streams are different experiments with different fixtures and settings.
- Correlation in the Section 6 output is sampled luminance correlation; it is not the paper’s per-channel table.
- Wrong-key or wrong-identifier processing has no authentication rejection guarantee. This pipeline has no HMAC authentication layer.
- NPCR/UACI, entropy, correlation, and NIST outcomes are empirical image/statistical checks only.

## Tests and reproduction status

From the original project directory, the test command is `../.venv/bin/python -m pytest tests -q`; the most recent post-split run passed **83 tests**, with 14 dependency deprecation warnings. `output/uct_colour_all_blocks/summary.csv` reports 24/24 exact UCT image recoveries and payload recoveries. NIST outputs are already generated and retained under `output/nist_sp800_22/`; no new NIST run was performed while preparing this report.

## Artifact provenance

- Report branch: `authenticated-tpe-paper`.
- Report source commit: `7bbe3cf32197b3bba5f5f868df90b9c417c4da66`.
- Worktree state at report-generation start: clean; report files were not yet present.
- Current verification environment: Python 3.11.0, NumPy 2.4.4, Pillow 12.0.0, scikit-image 0.25.2, pytest 8.4.2, Matplotlib 3.10.6.
- UCT inputs are under `input/uct_colour/`; SHA-256 is over the tracked TIFF file bytes:

| Input | SHA-256 |
|---|---|
| `input/uct_colour/airplane.tif` | `515d0a5105047916be9faed513330046be41a61f4b155e854731e512ce1f4c4a` |
| `input/uct_colour/baboon.tif` | `cd4456f2562dc352acee627428eb4e2ccaed5f53082ce0838d9fff6b8a3e3517` |
| `input/uct_colour/couple.tif` | `e1760e29f10762fe60349e2848b01065b69784d04848606dd8644b6a9a893288` |
| `input/uct_colour/girl.tif` | `d044fcfbea02123efdc167e596f45e839c39c2e1ca2ff841710ef4db15bc4dfb` |
| `input/uct_colour/lena.tif` | `d5cd280e7e970a31828fe2c91ead6c8ce3ea257d04b6eabbd8e254c6e1cce255` |
| `input/uct_colour/peppers.tif` | `208e8c6542e91a1b3d7d9457626b7577fc0d21affeb800435858cc83f2537649` |

Generated artifact groups have separate historical provenance: NIST STS 2.1.2 results were generated from source commit `55e99abf0693b1b5fd74ea34583091f27e5dbe19` with Python 3.11.0; Section 6 results from `3aafb0fa048953131424e2110166d26b602c73f7` with Python 3.13.9; the synthetic submission metrics from `8ec4bccef50d72ad4ae036d086914c480661a95f` with Python 3.13.9. The respective artifact provenance files under `output/nist_sp800_22/`, `output/section6/`, and `results/metrics.txt` provide run-specific settings. These different source revisions and fixtures are not one combined run.
