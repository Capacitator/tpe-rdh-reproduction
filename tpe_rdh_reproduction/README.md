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
- authorized recovery use: run the inverse pipeline with the same key, stored image identifier, and parameters to recover the payload and original image exactly.

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

- The paper's exact key-to-chaos conversion is not numerically specified, so the implementation uses a documented 256-bit key and image-identifier convention in `src/chaos.py`.
- `vartheta=10000.0` is an implementation inference from the paper's figure-style examples, not an explicit textual parameter.
- RDH can change block sums before substitution. The substitution stage then preserves the RDH-marked block sums exactly.
- Differential-security metrics are validation metrics for this implementation, not reproduction of the paper's reported security tables.

Missing:

- The authors' exact 256-bit key schedule, if it differs from the documented implementation convention.
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

The checked-in dependency pins were verified with Python 3.13.9. The exact source commit and initial working-tree state used for checked-in submission metrics are recorded in `results/metrics.txt`.

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
All repository tests pass.
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
source_commit_at_generation: 8ec4bccef50d72ad4ae036d086914c480661a95f
source_tree_state_at_generation: clean
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
entropy_encrypted: 7.987439406422887
correlation_original_horizontal: 0.9954550416497832
correlation_encrypted_horizontal: 0.11722325720278601
correlation_original_vertical: 0.9959389496754845
correlation_encrypted_vertical: 0.4062607276319208
correlation_original_diagonal: 0.9915082354583871
correlation_encrypted_diagonal: 0.40454563900899454
rdh_channel0_peak: 92
rdh_channel0_zero: 91
rdh_payload_bits_by_channel: (83, 83, 82)
rdh_total_payload_bits: 248
rdh_channel0_embedded_bits_including_overhead: 163
marked_to_encrypted_block_sums_preserved: True
thumbnail_max_abs_difference_marked_vs_encrypted: 0
thumbnail_max_abs_difference_original_vs_encrypted: 0
```

Timing values are written to `results/metrics.txt` and will vary by machine. The source fields record both the base commit and whether tracked files were modified when the artifact was generated; after committing a regenerated artifact, the repository commit that contains it will necessarily have a newer hash.

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

The generated `output/section6/provenance.txt` records the exact source revision
and deterministic experiment settings for those validation artifacts.

## Algorithm Notes

### Chaotic System

`src/chaos.py` implements the Cubic map, Sinusoidal map, and coupled 2D-CSM map. `generate_upsilon_matrices` produces key-dependent and image-dependent `Upsilon_P` and `Upsilon_S` matrices for a given image size. The implementation accepts a 256-bit key and an image identifier `T`, derives `x0`, `y0`, `r1`, `r2`, `kappa_1`, `T_tau`, and `kappa_2`, and uses the two-stage Section 5.1 iteration procedure. The complete key and identifier are bound into `kappa_2`, so identifiers that collide at the bounded `T_tau` step do not automatically produce identical matrices. The pipeline derives `T` from plaintext image bytes by default during encryption and returns it in `EncryptionResult.image_identifier`; callers can pass the complete `EncryptionResult` directly to `decrypt_rgb_image`.

The automatic image identifier is SHA-256 over a domain-separated canonical representation: `tpe-rdh:image-id:v1`, an RGB channel-order tag, the `uint8` dtype name, the three shape dimensions encoded as fixed-width integers, and the C-contiguous row-major plaintext pixel bytes. It hashes the in-memory image before encryption, not PNG/JPEG encoding or bytes obtained by saving and reloading the image.

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

- The 256-bit key is split into four 64-bit fields to derive `x0`, `y0`, `r1`, and `r2`.
- `kappa_1` is derived from `SHA-256(key || b"kappa_1")` in the range `128..1151`.
- Image identifier `T` is converted to `T_tau` with `SHA-256(T)` in the range `1..1024`.
- `kappa_2` is derived in the range `1..1024` from a domain-separated SHA-256 input containing the complete key, complete image identifier, and first-stage chaotic state. Binding the full identifier prevents `T_tau` collisions from automatically producing identical matrices. The bounded output is a runtime choice: the construction is collision-resistant, not mathematically injective over all possible images.
- `vartheta=10000.0` is inferred, not explicitly specified in the accessible text.
- `Upsilon_P` and `Upsilon_S` are generated from the x/y outputs of one 2D-CSM run.
- Sorting direction, tie handling, flattening order, and pairing order are implementation decisions documented in the code.
- RGB payload data is split into contiguous chunks and embedded across channels 0, 1, and 2, then concatenated during extraction.

## Reproducibility Checklist

Use these commands from the project root:

```bash
python -m pytest tests
python experiments/generate_submission_results.py
python experiments/final_demo.py
```

Expected core checks:

```text
tests: all repository tests pass
exact_recovery: True
payload_recovered: True
max_abs_error: 0
marked_to_encrypted_block_sums_preserved: True
```
