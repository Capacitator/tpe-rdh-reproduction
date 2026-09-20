# Experiments

This document describes the experiments used to check the project implementation.

## Datasets And Images

UCT colour standard images:

```text
airplane.tif  512x512 RGB
baboon.tif    512x512 RGB
couple.tif    256x256 RGB
girl.tif      256x256 RGB
lena.tif      512x512 RGB
peppers.tif   512x512 RGB
```

Source: https://www.dip.ee.uct.ac.za/imageproc/stdimages/colour/

Additional demo/validation images are loaded from `skimage.data`, including `coffee`, `chelsea`, `rocket`, and `hubble_deep_field`.

The original paper reports experiments on the Helen dataset. This project uses the UCT colour images and several `skimage.data` images because those images were easy to include and reproduce locally. The results below are therefore project validation results, not a copy of the authors' Helen-dataset tables.

## Block Sizes

The main validation block sizes are:

```text
b = 8, 16, 32, 64
```

The final clean demo uses:

```text
b = 16
```

## Metrics

Implemented metrics and checks:

- exact recovery by pixel equality;
- maximum absolute recovery error;
- exact payload recovery;
- PSNR and SSIM for original vs recovered images;
- post-RDH block-sum preservation, checking `marked_image` vs final encrypted image;
- adjacent-pixel correlation with 5,000 sampled pairs;
- NPCR and UACI for differential validation;
- embedding capacity before and after overhead;
- encryption+embedding and decryption+recovery runtime, excluding file I/O.

## Successful Results

Unit/integration tests:

```text
All repository tests pass.
```

UCT all-block validation:

```text
total runs: 24
successful runs: 24
failed runs: 0
exact recovery: true for all runs
max recovery error: 0 for all runs
payload recovery: true for all runs
post-RDH block-sum preservation: true for all runs
```

The UCT all-block summary is written to:

```text
output/uct_colour_all_blocks/summary.csv
```

Each regenerated Section 6 run writes `output/section6/provenance.txt`. It
records the source commit, tracked-tree state, interpreter version, image set,
and deterministic sampling/differential settings that produced the CSVs and
plots.

## Thumbnail Preservation

The correct thumbnail-preservation check in this implementation is:

```text
RDH-marked block sum == final encrypted block sum
```

This is because RDH may change pixel values before substitution. The substitution stage is the sum-preserving stage, so it preserves the block sums of the RDH-adjusted image.

## NPCR/UACI Notes

The NPCR/UACI experiment is included to study how this implementation behaves when the input image is changed slightly. It is not used as an exact reproduction of the paper's differential-security table.

Reasons:

- The paper says one pixel value within each block is altered, but does not specify the exact pixel position, channel, or direction.
- This project changes the top-left pixel of each block in the R channel by `+1`, or `-1` if the value is already `255`.
- With the default pipeline, the modified plaintext also derives a different image identifier and therefore different chaotic matrices. The measured NPCR/UACI values consequently reflect both the required same-key/different-image diversification and local substitution; they are not a substitution-only measurement.
- The paper's hidden key-generation/discard details may affect differential behavior, so these values remain project-validation results rather than a reproduction of the paper's table.

The experiment reports per-channel NPCR/UACI using the paper's Eq. (15)-Eq. (17) normalization, plus an `RGB_mean` summary row for convenience.

## Key-Sensitivity NPCR/UACI

`experiments/key_sensitivity_npcr_uaci.py` checks one-bit key sensitivity on
the six UCT colour images. It keeps the image, payload, image identifier, and
block size fixed, flips one key bit, and writes NPCR/UACI results to
`output/key_sensitivity/`. This is separate from the paper's Section 6.8
plaintext-difference NPCR/UACI table.

## Correlation Notes

The paper reports adjacent-pixel correlation for R, G, and B channels separately. In this project, `run_section6_experiments.py` computes correlation on RGB-to-luminance data with 5,000 sampled adjacent pairs. These values are used as a simple check that encryption lowers local correlation. A closer match to the paper would require separate R, G, and B channel measurements.

## Runtime Notes

Timing values are Python prototype timings. They exclude image file I/O and plotting. They are included to show the runtime of this project on the local environment, not to make a direct timing comparison with the authors' implementation.
