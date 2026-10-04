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

The checked-in same-key/different-image artifact reports image-derived identifiers differed: **yes**; Upsilon_P matrices differed: **yes**; Upsilon_S matrices differed: **yes**; ciphertexts differed: **yes**. It also records exact recovery and payload recovery for both demo images. This demonstrates implementation diversification for that fixture and is not evidence of cryptographic security. Source: `output/final_demo/final_demo_report.txt`.

## Validation results

### Exact recovery, payload, and capacity

`output/uct_colour_all_blocks/summary.csv` contains 24 image/block-size runs; 24/24 report exact image recovery and payload recovery. All rows report zero maximum recovery error and post-RDH block-sum preservation. The original images retain their native dimensions in this experiment.

The Section 6-style experiment contains 16 image/block-size cases; 16/16 report exact recovery (PSNR=inf, SSIM=1, maximum error 0). The synthetic demonstration reports exact image recovery and a recovered 248-bit payload.

### Thumbnail and block sums

The thumbnail stage artifact reports 215/255 block/channel sums unchanged at `rdh`; maximum absolute difference is 10 and mean absolute difference is 0.6118.
The thumbnail stage artifact reports 255/255 block/channel sums unchanged at `substitution`; maximum absolute difference is 0 and mean absolute difference is 0.0000.

The all-block UCT table separately records post-RDH block-sum preservation for every listed run. This distinction reflects that substitution preserves the RDH-marked sums, while RDH itself may change sums.

### NPCR and UACI

Across 16 Section 6 RGB-mean rows, NPCR is 96.93%–99.50% and UACI is 6.30%–26.60%. Across 64 per-channel rows, NPCR is 96.66%–99.55% and UACI is 6.15%–28.55%. The input perturbation is recorded in `output/section6/provenance.txt`; these are implementation diagnostics, not the paper's official security table.

The separate fixed-identifier one-bit-key sweep contains 24 rows: RGB NPCR 95.93%–99.47% and RGB UACI 9.70%–27.35%. Per-channel values are in `output/key_sensitivity/uct_key_sensitivity_npcr_uaci.csv`.

### Entropy and adjacent-pixel correlation

The checked-in synthetic demo reports image-level entropy 3.815429 bits for the source and 7.987439 bits for ciphertext; no multi-image entropy table is available. Section 6 correlation has 48 sampled luminance rows: original 0.7573–0.9905, encrypted -0.2054–0.6929. The experiment uses 5,000 deterministic adjacent pairs per direction. These are separate fixtures and calculations.

## NIST SP 800-22 Rev. 1a

The recorded run uses official NIST STS 2.1.2. Stream construction: 10 streams per category, 1,000,000 bits per stream, alpha 0.01. Full category conversions, key schedule and image order are recorded in `output/nist_sp800_22/provenance.txt`.

Selected tests: Frequency, BlockFrequency, CumulativeSums, Runs, LongestRun, Rank, FFT, NonOverlappingTemplate, OverlappingTemplate, Universal, ApproximateEntropy, RandomExcursions, RandomExcursionsVariant, Serial, LinearComplexity. Parameters: Block Frequency M=128; Non-overlap template m=9; Overlap template m=9; Approximate Entropy m=10; Serial m=16; Linear Complexity M=500; remaining suite defaults.

Aggregate component outcomes:

| Stream category | Pass | Fail | Not applicable | Total |
|---|---:|---:|---:|---:|
| chaotic | 484 | 1292 | 104 | 1880 |
| ciphertext | 410 | 1210 | 260 | 1880 |

Per-test component counts (pass / fail / not applicable):

| Test | Chaotic matrices | Final ciphertext |
|---|---:|---:|
| Frequency | 8 / 2 / 0 | 0 / 10 / 0 |
| BlockFrequency | 0 / 10 / 0 | 0 / 10 / 0 |
| CumulativeSums | 16 / 4 / 0 | 0 / 20 / 0 |
| Runs | 0 / 10 / 0 | 0 / 10 / 0 |
| LongestRun | 0 / 10 / 0 | 2 / 8 / 0 |
| Rank | 10 / 0 / 0 | 3 / 7 / 0 |
| FFT | 0 / 10 / 0 | 0 / 10 / 0 |
| NonOverlappingTemplate | 325 / 1155 / 0 | 389 / 1091 / 0 |
| OverlappingTemplate | 0 / 10 / 0 | 2 / 8 / 0 |
| Universal | 0 / 10 / 0 | 0 / 10 / 0 |
| ApproximateEntropy | 0 / 10 / 0 | 0 / 10 / 0 |
| RandomExcursions | 7 / 41 / 32 | 0 / 0 / 80 |
| RandomExcursionsVariant | 108 / 0 / 72 | 0 / 0 / 180 |
| Serial | 0 / 20 / 0 | 4 / 16 / 0 |
| LinearComplexity | 10 / 0 / 0 | 10 / 0 / 0 |

The results are mixed and contain substantial failures. Not applicable is not a pass. These statistical tests do not establish cryptographic security and are not a substitute for cryptanalysis.

## Assumptions and limitations

- Not reproduced: required original notebook/data/parameter was unavailable. The project evaluates its documented implementation on the checked-in fixtures and does not claim the paper authors' official experimental tables.
- Several paper details are underspecified: key-to-chaos conversion, the matrix-generation interpretation, sorting/tie behavior, block/pair order, `vartheta`, RGB payload/metadata layout, no-zero overhead encoding, and the exact Section 6.8 plaintext-change protocol. See `docs/paper_map.md`, `docs/IMPLEMENTATION_NOTES.md`, and `docs/SECTION5_NOTES.md`.
- The primary validation images differ from the paper’s Helen dataset. The `skimage.data` Section 6 results, UCT results, synthetic demo, key sensitivity sweep, and NIST streams are different experiments with different fixtures and settings.
- Correlation in the Section 6 output is sampled luminance correlation; it is not the paper’s per-channel table.
- Wrong-key or wrong-identifier processing has no authentication rejection guarantee. This pipeline has no HMAC authentication layer.
- NPCR/UACI, entropy, correlation, and NIST outcomes are empirical image/statistical checks only.






## Tests, reproduction, and provenance

The original-project suite command `python -m pytest tests -q` from `tpe_rdh_reproduction/` completed successfully: **83 passed, 14 warnings in 2.37s**.

### Artifact provenance

- Branch: `authenticated-tpe-paper`; source commit: `ec2661b690fa544b32b4d785fca3da46dc5a9603`.
- Source worktree at report generation: `dirty`; this records the actual state, including report-generation edits.
- Runtime: Python 3.11.0; numpy 2.4.4, pillow 12.0.0, scikit-image 0.25.2, pytest 8.4.2, matplotlib 3.10.6.
- UCT source inputs are TIFF files under `tpe_rdh_reproduction/input/uct_colour/`; hashes cover file bytes:

| Input | SHA-256 |
|---|---|
| `input/uct_colour/airplane.tif` | `515d0a5105047916be9faed513330046be41a61f4b155e854731e512ce1f4c4a` |
| `input/uct_colour/baboon.tif` | `cd4456f2562dc352acee627428eb4e2ccaed5f53082ce0838d9fff6b8a3e3517` |
| `input/uct_colour/couple.tif` | `e1760e29f10762fe60349e2848b01065b69784d04848606dd8644b6a9a893288` |
| `input/uct_colour/girl.tif` | `d044fcfbea02123efdc167e596f45e839c39c2e1ca2ff841710ef4db15bc4dfb` |
| `input/uct_colour/lena.tif` | `d5cd280e7e970a31828fe2c91ead6c8ce3ea257d04b6eabbd8e254c6e1cce255` |
| `input/uct_colour/peppers.tif` | `208e8c6542e91a1b3d7d9457626b7577fc0d21affeb800435858cc83f2537649` |

- Report-generation script: `tpe_rdh_reproduction/experiments/generate_original_report.py`.
- Exact generation command from repository root: `.venv/bin/python tpe_rdh_reproduction/experiments/generate_original_report.py`.
- Artifact paths: `tpe_rdh_reproduction/results/metrics.txt`; `tpe_rdh_reproduction/output/{uct_colour_all_blocks,section6,key_sensitivity,nist_sp800_22}/`; thumbnail sums: `tpe_rdh_reproduction/output/thumbnail_metrics.csv`.
- Historical run commits and runtime versions remain recorded separately in `output/nist_sp800_22/provenance.txt`, `output/section6/provenance.txt`, and `results/metrics.txt`. Those records are not represented as current clean-source runs.
- Paper source and documented assumptions: `tpe_rdh_reproduction/docs/paper_map.md`, `docs/IMPLEMENTATION_NOTES.md`, and `docs/SECTION5_NOTES.md`.
