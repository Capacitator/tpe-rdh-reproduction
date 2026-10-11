# Flowchart hybrid: block-preserving TPE with authentication

## What was checked

The professor’s flowchart proposes retaining the first method’s thumbnail/block effect and adding HMAC-SHA256, HMAC_DRBG block grouping, and reversible RCM authentication. The prior authenticated-only output did not use the legacy method’s within-block permutation, so it could not show the same 32×32 block effect.

I audited the legacy TPE stage and its RCM carrier capacity, then built a separate hybrid prototype in `src/block32_authenticated_tpe.py`; neither the original implementation nor the previous reports were modified. The experiment uses the six existing UCT color images and fixed, documented research-test keys/IDs. These are not production secrets.

## Ordering decision and reason

The legacy TPE/RDH path consists of within-block permutation, reversible data hiding, then a pairwise substitution that preserves the sum of each pixel pair and hence each 32×32 block’s sum. However, its post-substitution pixel pairs are not a usable RCM carrier for a 256-bit tag. On the Baboon run, the RCM T/O/N counts were 98,372 / 31,723 / 263,121, giving `T + O − N = −133,026` net bits. Net capacity is negative, so no RCM tag can fit after that substitution, even across the whole image. All six legacy post-substitution carriers have negative net capacity.

The hybrid therefore applies the authentication module’s reversible Step-1/Step-2, HMAC, HMAC_DRBG ordering and RCM marking at the capacity-adequate block-permuted/RDH carrier. The legacy pair-sum-preserving substitution is then applied as an outer reversible operation; decryption reverses it before authentication. This lets the visible block-TPE output and the authenticated reversible path coexist without changing the legacy substitution equations or falsifying results. It is an ordering adjustment and should be treated as a research prototype, not as an exact reproduction of a paper flowchart that mandates RCM after the legacy substitution.

## Group-capacity result

An RCM group needs at least 256 net slots (`T + O − N`) for a 256-bit HMAC-SHA256 tag. The HMAC_DRBG ordering is deterministic from the authentication key, channel, and image geometry. The existing protocol requires every 4-block group to fit; otherwise it atomically switches to a whole-image HMAC/RCM tag. The observed result was:

| Image | Net capacity across post-auth-Step-2 carrier | 4-block groups that fit | Legacy post-substitution net capacity |
|---|---:|---:|---:|
| Airplane | 250,706 | 191/192 | −132,962 |
| Baboon | 203,012 | 188/192 | −133,026 |
| Couple | 8,272 | 22/48 | −35,216 |
| Girl | 36,222 | 42/48 | −34,448 |
| Lena | 254,036 | 189/192 | −132,040 |
| Peppers | 206,736 | 183/192 | −128,360 |

Thus **all six final outputs use whole-image authentication fallback**. Authentication and exact recovery work, but this set does not achieve four-block tamper localization. The capacity audit is saved as `output/metrics/flowchart_hybrid/capacity_audit.csv`; it records every image and all groups.

## Six-image fidelity and recovery results

Full RGB PSNR compares the original pixel array to the encrypted pixel array. It is expected to be relatively low for encrypted images and is **not** the TPE thumbnail-preservation score. The block-thumbnail PSNR compares rounded RGB mean values for corresponding 32×32 blocks in the original and encrypted arrays; that is the relevant thumbnail-fidelity metric. SSIM is also computed on these thumbnails.

| Image | Full RGB PSNR: base → authenticated (dB) | 32×32 block-thumbnail PSNR: base → authenticated (dB) | Thumbnail SSIM: base → authenticated | Authentication | Exact image + payload recovery |
|---|---:|---:|---:|---|---|
| Airplane | 13.2544 → 12.7848 | 54.0178 → 36.4636 | 0.999879 → 0.993927 | Whole image | Pass |
| Baboon | 11.3812 → 11.2735 | 52.1988 → 39.5298 | 0.999952 → 0.997915 | Whole image | Pass |
| Couple | 16.4928 → 16.4355 | 54.4317 → 51.4699 | 0.999812 → 0.999591 | Whole image | Pass |
| Girl | 13.8179 → 13.7931 | 54.8360 → 51.4699 | 0.999922 → 0.999767 | Whole image | Pass |
| Lena | 12.4657 → 12.2437 | 51.1638 → 36.8573 | 0.999893 → 0.997616 | Whole image | Pass |
| Peppers | 12.2221 → 12.1111 | 49.8244 → 43.5740 | 0.999928 → 0.999202 | Whole image | Pass |
| **Mean** | **13.2724 → 13.1069** | **52.7454 → 43.2274** | **0.999898 → 0.998003** | **6/6 whole-image fallback** | **6/6 pass** |

Authentication marking has a measurable thumbnail cost, especially on Airplane and Lena. Those values are reported rather than hidden. It is not correct to call the post-marking thumbnail PSNR “preserved exactly.”

## Validation

- `python3 experiments/run_flowchart_hybrid.py` regenerates all six image pairs, checks HMAC verification, exact image recovery, and exact payload recovery, then writes `metrics.csv` and PNGs.
- `python3 -m pytest tests/test_block32_authenticated_tpe.py -q` checks authenticated round-trip, tamper rejection with plaintext withheld, wrong-ImageID rejection, and geometry validation.
- `python3 experiments/append_flowchart_results_to_gallery.py` appends the metrics and output comparisons to the currently open Word gallery without removing its earlier pages.

The generated six-image record is `output/metrics/flowchart_hybrid/metrics.csv`. The updated Word document contains the full-PSNR and block-thumbnail PSNR/SSIM table, the capacity table, and all six original/base/final image triplets.
