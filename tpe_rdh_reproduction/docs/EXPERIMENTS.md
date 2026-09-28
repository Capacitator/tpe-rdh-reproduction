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

## NIST SP 800-22 Rev. 1a Bitstream Validation

`experiments/run_nist_sp800_22.py` drives the NIST Statistical Test Suite
(STS) 2.1.2 executable on two categories of bitstreams from the actual
pipeline: the `Upsilon_P` and `Upsilon_S` chaotic matrices, and final encrypted
RGB images. This is an additional statistical validation of these selected
bitstreams. It is not a proof of cryptographic security and is not an exact
reproduction of the paper's official security tables. Its results are separate
from NPCR, UACI, entropy, correlation, exact recovery, and thumbnail-preservation
metrics.

The run uses 10 streams per category, 1,000,000 bits per stream, and default
STS test parameters at alpha 0.01. Images and ordering are listed in
`output/nist_sp800_22/stream_manifest.csv`; streams 1 and 2 use the same fixed
key on different images. The pipeline automatically derives each image
identifier from plaintext RGB pixels. Ciphertext conversion uses row-major
RGB `uint8` bytes, MSB first. Chaotic values use `floor((x+1)*128)`, clipped to
uint8, with `Upsilon_P` followed by `Upsilon_S`, row-major and MSB first. Each
stream is truncated to exactly 1,000,000 bits.

Download and build the official NIST STS 2.1.2 distribution, then run:

```bash
curl -L -o sts-2_1_2.zip https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip
unzip sts-2_1_2.zip
cd sts-2.1.2/sts-2.1.2
mkdir -p obj experiments/{AlgorithmTesting,BBS,CCG,G-SHA1,LCG,MODEXP,MS,QCG1,QCG2,XOR}
(cd experiments && bash ./create-dir-script)
make
cd /path/to/tpe_rdh_reproduction
python experiments/run_nist_sp800_22.py --sts-dir /path/to/sts-2.1.2/sts-2.1.2
```

The experiment records source revision, Python and runtime dependency
versions, STS version/source, exact command, image/key/identifier data, stream
conversion, lengths, test parameters, native reports, and parsed results. If
STS cannot be built or run, the command fails explicitly and does not substitute
unrelated metrics. NIST statistical results do not establish cryptographic
security and are separate from NPCR, UACI, entropy, correlation, exact recovery,
and thumbnail-preservation results.

### Sources and limitations

The authoritative sources are NIST's documentation/software page, SP 800-22
Rev. 1a, guide to the tests, publication page, and revision notice. The
`terrillmoore/NIST-Statistical-Test-Suite` GitHub repository is cited only as a
practical implementation reference; this experiment runs the official NIST
STS 2.1.2 distribution. Sources were accessed on 2026-09-28:

1. [NIST documentation and software](https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software)
2. [NIST SP 800-22 Rev. 1a PDF](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf)
3. [NIST guide to the statistical tests](https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software/guide-to-the-statistical-tests)
4. [NIST publication page](https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final) (published 2010-04-30)
5. [NIST revision notice](https://csrc.nist.gov/news/2022/decision-to-revise-nist-sp-800-22-rev-1a) (2022-04-19)
6. [Professor-provided practical implementation reference](https://github.com/terrillmoore/NIST-Statistical-Test-Suite)

SP 800-22 Rev. 1a provides statistical tests for random and pseudorandom
bitstreams. This suite is an additional statistical evaluation for this
project. Passing selected tests under stated parameters does not prove that the
encryption scheme is cryptographically secure. Statistical testing is not a
substitute for cryptanalysis. NIST's April 19, 2022 notice says the publication
is planned for revision and explicitly calls for clarifying its purpose and
rejecting its use for assessing cryptographic random number generators.
Accordingly, report results as “passed/failed the selected statistical tests
under the stated parameters,” never as “proved secure.” NIST results remain
distinct from NPCR, UACI, entropy, correlation, exact-recovery, and
thumbnail-preservation metrics.

The implementation retains documented paper ambiguities: key-to-chaos
conversion and image identifier hashing, `T_tau`, `kappa_2`, RDH metadata, and
`vartheta` remain project implementation decisions or inferences.
