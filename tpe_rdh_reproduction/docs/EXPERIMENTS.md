# Experiments

This document describes the current validation experiments and their limitations.

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

The paper reports experiments on the Helen dataset. The current experiments are validation runs for this reproduction and should not be claimed as exact reproduction of the authors' tables.

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
64 passed
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

## Thumbnail Preservation

The correct thumbnail-preservation check in this implementation is:

```text
RDH-marked block sum == final encrypted block sum
```

This is because RDH may change pixel values before substitution. The substitution stage is the sum-preserving stage, so it preserves the block sums of the RDH-adjusted image.

## NPCR/UACI Limitation

The current NPCR/UACI experiment is useful for auditing this reproduction, but the results are not claimed as reproduction of the paper's differential-security numbers.

Reasons:

- The paper says one pixel value within each block is altered, but does not specify the exact pixel position, channel, or direction.
- Current code changes the top-left pixel of each block in the R channel by `+1`, or `-1` if the value is already `255`.
- The current implementation has local block/pair behavior and does not show the high avalanche behavior reported by the paper.
- The paper's hidden key-generation/discard details may affect differential behavior.

The experiment reports per-channel NPCR/UACI using the paper's Eq. (15)-Eq. (17) normalization, plus an `RGB_mean` summary row for convenience.

## Correlation Limitation

The paper reports adjacent-pixel correlation for R, G, and B channels separately. The current `run_section6_experiments.py` helper computes correlation on RGB-to-luminance data with 5,000 sampled adjacent pairs. Those values are useful for sanity-checking that encryption lowers local correlation, but they should not be presented as the paper's per-channel correlation reproduction until the metric is split by R/G/B.

## Runtime Limitation

Timing values are Python prototype timings. They exclude image file I/O and plotting. They should not be compared directly to the paper unless the authors' implementation language, hardware behavior, threading, and IO policy are matched.
