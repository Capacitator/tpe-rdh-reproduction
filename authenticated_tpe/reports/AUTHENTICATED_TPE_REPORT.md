# Authenticated-TPE experimental results

The evaluation uses six public UCT images because the eight CelebA-HQ source files were unavailable. Authenticated-TPE is implemented with a fixed 32×32 block size; authenticated 8×8 and 16×16 results are therefore not reported.

## Scope and method

The evaluation uses six public UCT images because the exact eight CelebA-HQ source files were unavailable. These are adapted UCT experiments, not an exact reproduction of the CelebA-HQ dataset. The six images are airplane, baboon, couple, girl, lena, and peppers. Authenticated-TPE is implemented with a fixed 32×32 block size; authenticated 8×8 and 16×16 results are therefore not reported.

All six clean cases use group mode and 192 tags (49,152 tag bits). Protection and verification times exclude file I/O. Step-2 is the image-derived keyed intermediate before authentication-tag embedding, not a chaotic sequence. Entropy uses 256-bin uint8 histograms. Correlation values are per-channel RGB Pearson coefficients from 5,000 deterministic sampled neighbor pairs (seed 20261006), with zero-variance samples treated as N/A. NIST streams use row-major RGB uint8 serialization, MSB-first bit packing, and the first 1,000,000 bits.

## Updated clean-image and recovery results

| Image | Mode | Tags | Pairs used | Protection (s) | Verification (s) | Marked vs Step-2 PSNR (dB) | Marked vs Step-2 SSIM | Recovered MSE | Recovered PSNR (dB) | Recovered SSIM | Max error | Authenticated | Exact recovery |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| airplane | group | 192 | 54,422 | 1.801782667 | 1.982827250 | 30.197769 | 0.964932587 | 0 | ∞ | 1.0 | 0 | Yes | Yes |
| baboon | group | 192 | 57,474 | 1.794341667 | 1.992045625 | 27.771427 | 0.963104519 | 0 | ∞ | 1.0 | 0 | Yes | Yes |
| couple | group | 192 | 80,778 | 1.891289376 | 2.164496500 | 32.624797 | 0.965344652 | 0 | ∞ | 1.0 | 0 | Yes | Yes |
| girl | group | 192 | 62,248 | 1.798324209 | 2.004182667 | 30.107185 | 0.953497455 | 0 | ∞ | 1.0 | 0 | Yes | Yes |
| lena | group | 192 | 55,012 | 1.765184042 | 1.952447917 | 28.060002 | 0.951909622 | 0 | ∞ | 1.0 | 0 | Yes | Yes |
| peppers | group | 192 | 57,422 | 1.794741292 | 1.979297791 | 29.030458 | 0.953634973 | 0 | ∞ | 1.0 | 0 | Yes | Yes |

Mean protection time: 1.807610542 s (range 1.765184042–1.891289376); mean verification time: 2.012549625 s (range 1.952447917–2.164496500). Mean marked-vs-Step-2 PSNR: 29.631940 dB; mean SSIM: 0.958737301. All six saved recovery arrays match their source arrays exactly (MSE 0, maximum error 0, PSNR infinite, SSIM 1.0); authentication passed 6/6.

## Entropy

H = −Σ p(i) log₂ p(i), with 256 bins. R, G, and B are computed separately; RGB pooled treats each channel sample as one scalar observation.

| Image | R | G | B | RGB pooled |
|---|---:|---:|---:|---:|
| airplane | 7.135636527 | 7.180702424 | 6.784789838 | 7.064999369 |
| baboon | 7.807437634 | 7.683203666 | 7.842778310 | 7.854161678 |
| couple | 6.758240761 | 6.307566009 | 6.192004474 | 6.463652151 |
| girl | 7.428313126 | 7.077189296 | 6.942157102 | 7.231297119 |
| lena | 7.434802831 | 7.746658523 | 7.350288629 | 7.861728222 |
| peppers | 7.583238681 | 7.630465959 | 7.239497768 | 7.761418610 |

Across 24 individual-channel values, mean entropy is 7.265092863 bits (range 6.192004474–7.861728222). Channel ranges: R 6.758240761–7.807437634; G 6.307566009–7.746658523; B 6.192004474–7.842778310. Mean RGB-pooled entropy is 7.372876191 bits.

## Neighboring-pixel correlations

Each row below averages the nine per-channel/direction coefficients for the image; full per-direction and per-channel values are in `authenticated_tpe/output/experimental_results_template/correlation_results.csv`.

| Image | Original mean | Final marked mean | Original range | Final marked range |
|---|---:|---:|---:|---:|
| airplane | 0.949037 | 0.553908 | 0.917522–0.972059 | 0.430377–0.669321 |
| baboon | 0.850506 | 0.586416 | 0.736581–0.925287 | 0.506628–0.681138 |
| couple | 0.981448 | 0.814021 | 0.968953–0.988454 | 0.759833–0.860174 |
| girl | 0.988654 | 0.800931 | 0.980839–0.993446 | 0.720601–0.847417 |
| lena | 0.962103 | 0.616838 | 0.916806–0.990414 | 0.431462–0.805012 |
| peppers | 0.965039 | 0.752010 | 0.945051–0.981697 | 0.567518–0.874507 |

Across the 54 original coefficients, mean/range is 0.949464507 (0.736580896–0.993446091); across the 54 final marked coefficients, mean/range is 0.687353889 (0.430377300–0.874507128). Direction- and channel-level ranges are present in the CSV.

## Security and recovery

- Clean authentication: 6/6; exact recovery: 6/6; group mode: 6/6; natural-image fallback: 0/6. A separately constructed fixture exercises whole-image fallback and is excluded from the six-image average.
- Tamper/credential rejection: 7/7; wrong key 1/1; wrong ImageID 1/1; protected-image replacement rejected. Plaintext release after failed authentication: 0/7.
- Fixed-ImageID plaintext difference: six-image mean pooled-RGB NPCR/UACI 1.09905667% / 0.00875461%.
- Image-specific-ImageID plaintext difference: separate six-image mean pooled-RGB NPCR/UACI 93.53758494% / 8.03501071%.
- One-bit key sensitivity: separate six-image mean pooled-RGB NPCR/UACI 94.40517426% / 8.09181321%.
- Same key and fixed ImageID produced different Step-1, Step-2, and final marked arrays for airplane and baboon; both recovered exactly. The image-specific-ID comparison is separate. NPCR/UACI are diagnostics, not security proofs.

## Improved NIST SP 800-22 results

The official NIST STS 2.1.2 suite was run separately on the Step-2 image-derived keyed intermediate and final marked RGB. Each category contains 100 streams, each one million bits, using 100 distinct deterministic UserKey and ImageID fixtures and six UCT images selected round-robin. Step-2 is not called chaotic.

| Category | Pass | Fail | N/A | Component outcomes |
|---|---:|---:|---:|---:|
| Step-2 image-derived keyed intermediate | 1,838 | 14,362 | 2,600 | 18,800 |
| Final marked RGB | 1,938 | 14,262 | 2,600 | 18,800 |

These are preliminary statistical diagnostics; no overall NIST pass is claimed. SP 800-22 is not a cryptographic security proof. Detailed p-values, component statuses, pass proportions, and second-level uniformity results are in `authenticated_tpe/output/nist_sp800_22_improved/results.csv` and `per_test_summary.csv`.

## Template coverage and remaining items

The exact CelebA-HQ source files are unavailable. Six public UCT images were used as adapted experiments. The implementation has a fixed 32×32 authenticated block size; authenticated 8×8 and 16×16 results are N/A — authenticated-TPE implementation supports fixed 32×32 blocks only. All available entropy and correlation data for these six images are included.

## COPY-PASTE REPORT FOR PROFESSOR

### Authenticated-TPE clean-image results

| Image | Mode | Tags | Pairs | Protection (s) | Verification (s) | Marked vs Step-2 PSNR (dB) | SSIM | Recovered MSE | Recovered PSNR | Recovered SSIM | Exact |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| airplane | group | 192 | 54,422 | 1.801782667 | 1.982827250 | 30.197769 | 0.964932587 | 0 | ∞ | 1.0 | Yes |
| baboon | group | 192 | 57,474 | 1.794341667 | 1.992045625 | 27.771427 | 0.963104519 | 0 | ∞ | 1.0 | Yes |
| couple | group | 192 | 80,778 | 1.891289376 | 2.164496500 | 32.624797 | 0.965344652 | 0 | ∞ | 1.0 | Yes |
| girl | group | 192 | 62,248 | 1.798324209 | 2.004182667 | 30.107185 | 0.953497455 | 0 | ∞ | 1.0 | Yes |
| lena | group | 192 | 55,012 | 1.765184042 | 1.952447917 | 28.060002 | 0.951909622 | 0 | ∞ | 1.0 | Yes |
| peppers | group | 192 | 57,422 | 1.794741292 | 1.979297791 | 29.030458 | 0.953634973 | 0 | ∞ | 1.0 | Yes |

Mean protection 1.807610542 s (min–max 1.765184042–1.891289376); mean verification 2.012549625 s (min–max 1.952447917–2.164496500). Mean marked-vs-Step-2 PSNR/SSIM: 29.631940 dB / 0.958737301. Exact recovery and authentication: 6/6 each.

### Entropy

| Image | R | G | B | RGB pooled |
|---|---:|---:|---:|---:|
| airplane | 7.135636527 | 7.180702424 | 6.784789838 | 7.064999369 |
| baboon | 7.807437634 | 7.683203666 | 7.842778310 | 7.854161678 |
| couple | 6.758240761 | 6.307566009 | 6.192004474 | 6.463652151 |
| girl | 7.428313126 | 7.077189296 | 6.942157102 | 7.231297119 |
| lena | 7.434802831 | 7.746658523 | 7.350288629 | 7.861728222 |
| peppers | 7.583238681 | 7.630465959 | 7.239497768 | 7.761418610 |

Individual-channel mean/range: 7.265092863 bits / 6.192004474–7.861728222; pooled RGB mean: 7.372876191 bits. R/G/B ranges: 6.758241–7.807438 / 6.307566–7.746659 / 6.192004–7.842778 bits.

### Neighboring-pixel correlation by image

| Image | Original mean (range) | Final marked mean (range) |
|---|---:|---:|
| airplane | 0.949037 (0.917522–0.972059) | 0.553908 (0.430377–0.669321) |
| baboon | 0.850506 (0.736581–0.925287) | 0.586416 (0.506628–0.681138) |
| couple | 0.981448 (0.968953–0.988454) | 0.814021 (0.759833–0.860174) |
| girl | 0.988654 (0.980839–0.993446) | 0.800931 (0.720601–0.847417) |
| lena | 0.962103 (0.916806–0.990414) | 0.616838 (0.431462–0.805012) |
| peppers | 0.965039 (0.945051–0.981697) | 0.752010 (0.567518–0.874507) |

Across 54 coefficients, original mean/range 0.949465 (0.736581–0.993446); final marked 0.687354 (0.430377–0.874507). Full per-image, direction, channel rows and channel ranges are in the correlation CSV.

### Security and recovery

Clean authentication 6/6; exact recovery 6/6; group mode 6/6; natural fallback 0/6. Constructed fallback is a separate fixture. Tamper/credential rejection 7/7; wrong key 1/1; wrong ImageID 1/1; image replacement rejected; plaintext released after failed authentication 0/7.
Separate pooled-RGB plaintext-difference tests: fixed ImageID NPCR/UACI 1.09905667% / 0.00875461%; changed image-specific ImageID 93.53758494% / 8.03501071%. One-bit key sensitivity: 94.40517426% / 8.09181321%.
Same key and fixed ImageID yielded different Step-1, Step-2, and final marked arrays for airplane and baboon; both recovered exactly. Image-specific-ID results are a separate experiment.

### Improved NIST evaluation

Official STS 2.1.2, α=0.01; 100 streams/category, 1,000,000 bits/stream; 100 unique deterministic key and ImageID fixtures; six UCT images round-robin. Step-2 image-derived keyed intermediate: 1,838 pass / 14,362 fail / 2,600 N/A. Final marked RGB: 1,938 / 14,262 / 2,600. Preliminary statistical diagnostics; no overall pass claimed; SP 800-22 is not a security proof.

### Remaining items

Exact CelebA-HQ images are unavailable. Authenticated 8×8 and 16×16 results are N/A — authenticated-TPE implementation supports fixed 32×32 blocks only. Larger-scale or additional-dataset evaluation requires the unavailable source images.
