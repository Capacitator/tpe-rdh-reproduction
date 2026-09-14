# Dual-Mode TPE/RDH Reproduction Prototype

Python reproduction prototype for:

An, D., Pu, X., Lu, J., & Xia, X. (2026). "A dual-mode thumbnail-preserving encryption scheme based on chaotic system and reversible data hiding." Journal of King Saud University Computer and Information Sciences. https://doi.org/10.1007/s44443-026-00479-y

This is a reproduction prototype for the paper "A dual-mode thumbnail-preserving encryption scheme based on chaotic system and reversible data hiding." It implements the executable stages that can be reconstructed from the accessible paper text. Some paper details, especially the 256-bit key-to-chaos conversion, exact mode semantics, and RDH metadata format, are not specified sufficiently in the accessible source, so this project documents those parts as implementation limitations.

## Purpose

The project demonstrates a thumbnail-preserving encryption pipeline with reversible data hiding:

1. Generate chaotic values with the paper's 2D-CSM map.
2. Reshape chaotic sequences into `Upsilon_P` and `Upsilon_S`.
3. Permute pixels inside thumbnail blocks using sorted `Upsilon_P`.
4. Embed payload/metadata using histogram-shifting RDH.
5. Encrypt pixel values with sum-preserving two-pixel substitution controlled by `Upsilon_S`.
6. Decrypt, extract payload bits, recover the RDH carrier, and inverse-permute the image.

The "dual-mode" concept is handled as two ways of using the encrypted result:

- public/preview mode: the encrypted image preserves the coarse block-average thumbnail after RDH marking;
- authorized recovery mode: using the same parameters, the receiver reverses substitution, extracts RDH data, and exactly recovers the original image.

The current code does not expose two separately named encryption APIs called "Mode 1" and "Mode 2". This is recorded as a project limitation.

In this repository, "dual-mode" means:

- preview use: inspect the final encrypted image as a coarse thumbnail of the RDH-marked image;
- authorized recovery use: run the inverse pipeline with the same explicit parameters to recover the payload and original image exactly.

It does not mean that the code implements two separately selectable paper-defined encryption modes.

## Current Status

Working:

- 2D-CSM chaotic map and chaotic matrix generation.
- Block-wise permutation and inverse permutation.
- Histogram-shifting RDH embedding, extraction, and recovery.
- Pair-wise sum-preserving substitution and inverse substitution.
- Integrated RGB encryption/decryption pipeline.
- Exact image recovery and payload recovery in tests and experiments.
- Thumbnail/block-sum validation for the substitution stage.
- Reproducible submission result generation in `results/`.

Partially working / limitations:

- The paper's key-to-chaos conversion, `kappa_1`, `T`, `T_tau`, and `kappa_2` are not numerically specified, so the implementation uses explicit parameters.
- `vartheta=10000.0` is an implementation inference from the paper's figure-style examples, not an explicit textual parameter.
- RDH can change block sums before substitution. The substitution stage then preserves the RDH-marked block sums exactly.
- Differential-security metrics are validation metrics for this implementation, not reproduction of the paper's reported security tables.

Missing:

- A fully specified 256-bit key schedule from the paper.
- A paper-defined payload/overhead binary format, so this implementation uses a documented metadata header.
- Separate named APIs for two paper modes, if the authors intended them as separately selectable algorithms.

## Repository Structure

```text
tpe_rdh_reproduction/
  docs/
    paper_map.md
    IMPLEMENTATION_NOTES.md
    EXPERIMENTS.md
  experiments/
    generate_submission_results.py
    final_demo.py
    run_section6_experiments.py
    uct_all_blocks_outputs.py
    validate_thumbnail.py
  input/
    uct_colour/
  output/
    generated experiment outputs; see output/README.md
  results/
    submission-ready generated outputs
  src/
    chaos.py
    permutation.py
    rdh.py
    substitution.py
    pipeline.py
  tests/
    test_*.py
  requirements.txt
  README.md
```

## Installation

From inside `tpe_rdh_reproduction/`:

The checked-in dependency pins were verified with Python 3.13.9. The checked-in submission metrics were regenerated from commit `5f0b6f55dab01439be4de1ec83d1c385c7fbf637`.

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On macOS/Linux:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run Tests

```bash
python -m pytest tests
```

Verified result in the current workspace:

```text
65 passed
```

## Generate Submission Results

This command creates a safe deterministic RGB test image, runs the full current pipeline, and writes presentable results:

```bash
python experiments/generate_submission_results.py
```

Generated files:

```text
results/
  original.png
  encrypted.png
  thumbnail.png
  decrypted.png
  metrics.txt
```

Representative checked-in metrics from the deterministic synthetic submission image:

```text
source_commit_at_generation: 5f0b6f55dab01439be4de1ec83d1c385c7fbf637
python_version: 3.13.9
requirements: numpy==2.4.4, pillow==12.0.0, opencv-python==4.13.0.92, matplotlib==3.10.6, scikit-image==0.25.2, pytest==8.4.2
image_shape: (512, 512, 3)
block_size: 16
thumbnail_shape: (32, 32, 3)
payload_bytes: 31
payload_bits: 248
payload_recovered: True
exact_recovery: True
max_abs_error: 0
mse_original_recovered: 0.0
psnr_original_recovered: inf
ssim_original_recovered: 1.0
entropy_original: 3.8154290297300544
entropy_encrypted: 7.987381868179968
correlation_original_horizontal: 0.9954550416497832
correlation_encrypted_horizontal: 0.11602307522818449
correlation_original_vertical: 0.9959389496754845
correlation_encrypted_vertical: 0.4038360486384358
correlation_original_diagonal: 0.9915082354583871
correlation_encrypted_diagonal: 0.4055012496129004
rdh_channel0_peak: 92
rdh_channel0_zero: 91
rdh_channel0_payload_bits: 248
rdh_channel0_embedded_bits_including_overhead: 328
marked_to_encrypted_block_sums_preserved: True
thumbnail_max_abs_difference_marked_vs_encrypted: 0
thumbnail_max_abs_difference_original_vs_encrypted: 0
```

Timing values are written to `results/metrics.txt` and will vary by machine. The `source_commit_at_generation` field records the clean checkout used to generate the artifact; after committing the regenerated file, the repository commit that contains it will necessarily have a newer hash.

## Other Useful Runs

Clean end-to-end demo on a `skimage.data` image:

```bash
python experiments/final_demo.py
```

Outputs:

```text
output/final_demo/
  01_original.png
  02_permutation_output.png
  03_rdh_marked_output.png
  04_final_encrypted.png
  05_recovered.png
  06_extracted_payload.txt
  final_demo_report.txt
  final_demo_stages.png
```

UCT image validation for `b = 8, 16, 32, 64`:

```bash
python experiments/uct_all_blocks_outputs.py
```

Current result:

```text
total_runs=24
successful_runs=24
failed_runs=0
exact recovery: True for all runs
payload recovery: True for all runs
block_sum_preserved: True for all runs
```

These runs use six UCT colour standard images. The paper's published tables use the Helen dataset, so the UCT results are reported as project validation results.

Section 6-style validation metrics:

```bash
python experiments/run_section6_experiments.py
```

This writes CSV files and plots under:

```text
output/section6/
```

## Algorithm Notes

### Chaotic System

`src/chaos.py` implements the Cubic map, Sinusoidal map, and coupled 2D-CSM map. `generate_upsilon_matrices` produces `Upsilon_P` and `Upsilon_S` for a given image size.

### Permutation

`src/permutation.py` partitions the image into `b x b` blocks. For each block, the matching `Upsilon_P` block is flattened in row-major order and sorted with stable ascending `np.argsort`. The sorted indices reorder the image pixels inside the block.

### RDH

`src/rdh.py` implements histogram-shifting RDH for one channel. It selects a peak point `P` and zero point `Z`, stores `P/Z` in the first 16 top-row LSBs, embeds metadata plus payload bits, and can recover the exact carrier.

### Substitution

`src/substitution.py` implements the paper's two-pixel same-sum mapping:

- `same_sum_pair_count`
- `pair_to_index`
- `chaotic_pair_delta`
- modular index encryption
- `index_to_pair`
- inverse substitution

The implementation uses `abs(Upsilon_S)` before forming chaotic value pairs.

### Thumbnail Preservation

The substitution stage preserves each two-pixel sum, so it preserves each RDH-marked block sum. Since a block-average thumbnail depends on block sums, the encrypted image preserves the thumbnail of the RDH-marked image. In the generated submission result, the marked-vs-encrypted thumbnail maximum absolute difference is `0`.

RDH itself can change block sums before substitution. Therefore exact original-vs-encrypted thumbnail equality is not guaranteed in general; the checked-in synthetic submission image happens to report `thumbnail_max_abs_difference_original_vs_encrypted: 0`.

## Known Assumptions

- `x0=0.3`, `y0=0.2`, `r1=50`, `r2=50` are passed explicitly.
- `discard_count=0` is used because the paper does not numerically define `kappa_1`, `T`, `T_tau`, or `kappa_2`.
- `vartheta=10000.0` is inferred, not explicitly specified in the accessible text.
- `Upsilon_P` and `Upsilon_S` are generated from the x/y outputs of one 2D-CSM run.
- Sorting direction, tie handling, flattening order, and pairing order are implementation decisions documented in the code.
- RGB payload data is embedded in channel 0; channels 1 and 2 receive empty RDH payloads so their metadata remains recoverable.

## Reproducibility Checklist

Use these commands from the project root:

```bash
python -m pytest tests
python experiments/generate_submission_results.py
python experiments/final_demo.py
```

Expected core checks:

```text
tests: 65 passed
exact_recovery: True
payload_recovered: True
max_abs_error: 0
marked_to_encrypted_block_sums_preserved: True
```
