# TPE-RDH Reproduction

Academic reproduction/prototype for the paper:

An, D., Pu, X., Lu, J., & Xia, X. (2026). "A dual-mode thumbnail-preserving encryption scheme based on chaotic system and reversible data hiding." Journal of King Saud University Computer and Information Sciences. https://doi.org/10.1007/s44443-026-00479-y

This repository is not the authors' original source code. It is a readable Python reproduction built to help a master's student or researcher understand, test, and explain the paper's core algorithm.

## Method In One Paragraph

The paper protects RGB images while keeping a coarse thumbnail-like preview. The current reproduction first generates chaotic matrices from the paper's 2D-CSM map, then permutes pixels inside fixed-size thumbnail blocks, embeds extra information using histogram-shifting reversible data hiding (RDH), and finally applies two-pixel sum-preserving substitution encryption. The substitution step changes pixel values while keeping each pixel-pair sum fixed, which preserves the block-average thumbnail of the RDH-adjusted image.

## Pipeline

```text
Image
  -> block permutation
  -> RDH
  -> sum-preserving substitution
  -> encrypted image

Encrypted image
  -> inverse substitution
  -> RDH extraction and recovery
  -> inverse block permutation
  -> recovered image + extracted payload
```

`Upsilon_P` controls Section 5.2 permutation. Each `b x b` block of `Upsilon_P` is sorted, and the sorted chaotic positions define how pixels are rearranged inside the matching image block.

`Upsilon_S` controls Section 5.4 substitution. Its values are converted to non-negative `Upsilon_S'`, paired with image pixels, and used in Eq. (6) to calculate the modular index shift for each two-pixel same-sum group.

## Install

From a fresh clone:

```text
cd tpe_rdh_reproduction
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On macOS/Linux, activate with:

```text
source .venv/bin/activate
```

## Run Tests

From the repository root that contains `tpe_rdh_reproduction/`:

```text
python -m pytest tpe_rdh_reproduction\tests
```

From inside `tpe_rdh_reproduction/`, use:

```text
python -m pytest tests
```

Current result at cleanup time:

```text
64 passed
```

## Run Demos

From the repository root:

```text
python tpe_rdh_reproduction\experiments\plot_chaos.py
python tpe_rdh_reproduction\experiments\plot_upsilon_matrices.py
python tpe_rdh_reproduction\experiments\demo_permutation.py
python tpe_rdh_reproduction\experiments\demo_rdh.py
python tpe_rdh_reproduction\experiments\demo_substitution.py
python tpe_rdh_reproduction\experiments\demo_pipeline.py
python tpe_rdh_reproduction\experiments\final_demo.py
```

The cleanest single demonstration is:

```text
python tpe_rdh_reproduction\experiments\final_demo.py
```

It writes original, permutation output, RDH marked output, final encrypted image, recovered image, extracted payload, and a side-by-side figure to `output/final_demo/`.

## UCT Colour-Image Experiments

The UCT source page lists exactly six colour test images:

```text
airplane.tif
baboon.tif
couple.tif
girl.tif
lena.tif
peppers.tif
```

Source: https://www.dip.ee.uct.ac.za/imageproc/stdimages/colour/

If the images are not already present under `input/uct_colour/`, download the six `.tif` files from that page into that folder.

Run all six images for `b = 8, 16, 32, 64`:

```text
python tpe_rdh_reproduction\experiments\uct_all_blocks_outputs.py
```

Output summary:

```text
output/uct_colour_all_blocks/summary.csv
```

Run the broader Section 6-style validation on natural images:

```text
python tpe_rdh_reproduction\experiments\run_section6_experiments.py
```

## Project Structure

```text
tpe_rdh_reproduction/
  docs/
    paper_map.md              # paper sections, equations, and ambiguities
    SECTION5_NOTES.md         # implementation checklist and pseudocode
    IMPLEMENTATION_NOTES.md   # paper-step to code mapping and assumptions
    EXPERIMENTS.md            # datasets, metrics, results, and limitations
  experiments/
    demo_*.py                 # small component demos
    final_demo.py             # clean end-to-end demonstration
    run_section6_experiments.py
    uct_all_blocks_outputs.py
    uct_b16_stage_outputs.py
    validate_thumbnail.py
  input/
    uct_colour/               # UCT colour test images when downloaded
  output/
    ...                       # generated figures, CSVs, and demo images
  src/
    chaos.py                  # Eqs. (2)-(4), Section 5.1 matrices
    permutation.py            # Section 5.2 permutation and inverse
    rdh.py                    # Section 5.3 RDH and recovery
    substitution.py           # Section 5.4 Eqs. (6)-(10)
    pipeline.py               # Section 5.2-5.5 integration
  tests/
    test_*.py                 # component and integration tests
  requirements.txt
  README.md
```

## Current Validation Results

Core tests:

```text
64 passed
```

UCT colour images, all block sizes `8, 16, 32, 64`:

```text
total runs: 24
successful runs: 24
failed runs: 0
exact recovery: yes for all runs
maximum recovery error: 0 for all runs
payload recovery: yes for all runs
post-RDH block-sum preservation: yes for all runs
```

Final demo:

```text
image: skimage.data.coffee resized to 512x512 RGB
block size: 16
vartheta: 10000.0
exact recovery: yes
max recovery error: 0
payload recovered: yes
```

Section 6-style validation currently demonstrates exact recovery and basic security/quality metrics, but the NPCR/UACI values and luminance-only correlation values are not claimed to reproduce the paper's reported security tables. See `docs/EXPERIMENTS.md`.

## Implementation Assumptions And Paper Ambiguities

The paper is treated as the source of truth. When the accessible text does not specify a detail needed for executable code, this reproduction uses an explicit implementation decision instead of silently inventing a paper claim.

Known assumptions:

- Key conversion is not specified. The implementation uses explicit parameters `x0=0.3`, `y0=0.2`, `r1=50`, `r2=50`.
- `kappa_1`, `T`, `T_tau`, and `kappa_2` are not numerically specified. The current demo/reproduction configuration uses `discard_count=0`.
- `vartheta=10000.0` is an inference from Fig. 4-style numeric examples, not an explicit textual parameter.
- `Upsilon_P` and `Upsilon_S` are generated from the x/y outputs of one deterministic 2D-CSM run. The paper says two independent chaotic matrices are generated but does not fully specify the construction.
- Permutation uses row-major flattening and stable ascending sort of each `Upsilon_P` block.
- Substitution pairs pixels and `Upsilon_S` values in row-major flattened order.
- RDH uses an explicit metadata header because the paper does not define payload length, overhead serialization, or coordinate encoding.
- The first 16 top-row pixels are excluded from RDH histogram shifting and embedding so P/Z storage can be recovered exactly.
- RGB payload embedding uses channel 0 for the actual payload; channels 1 and 2 receive empty RDH payloads so they remain recoverable.
- Differential NPCR/UACI validation changes the top-left R-channel pixel of each block by `+1`, or `-1` if the value is already `255`, because the paper does not specify the exact changed pixel/channel/direction.

## Notes For Researchers

This code is deliberately simple and modular. The important reversible pieces are tested independently before being composed. Exact recovery is verified with pixel equality, not visual similarity. Generated experiment results are useful for understanding this reproduction, but should not be presented as the authors' official numbers unless all paper settings, datasets, and hidden implementation details are matched.
