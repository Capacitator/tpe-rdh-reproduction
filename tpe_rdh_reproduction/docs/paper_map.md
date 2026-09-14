# Paper Map: Dual-Mode TPE With Chaotic System and RDH

Primary source: An, D., Pu, X., Lu, J., & Xia, X. (2026). "A dual-mode thumbnail-preserving encryption scheme based on chaotic system and reversible data hiding." Journal of King Saud University Computer and Information Sciences. https://doi.org/10.1007/s44443-026-00479-y

## 1. Simple Explanation

The paper proposes an image protection method that keeps an encrypted image visually previewable as a thumbnail while hiding detailed private content and embedding extra metadata that can later be extracted without loss. The method first scrambles pixel positions inside thumbnail blocks using a new two-dimensional chaotic map, then embeds non-visual data with histogram-shifting reversible data hiding, and finally changes pixel values in two-pixel groups with sum-preserving substitution encryption so each thumbnail block keeps the same coarse brightness information.

## 2. Complete Encryption Pipeline

1. Load an RGB image and split it into separate color-channel matrices.
2. Generate chaotic sequences with the proposed 2D-CSM map from parameters/key material.
3. Discard transient chaotic iterations and dynamic image-identifier-dependent iterations.
4. Reshape valid chaotic sequences into two chaotic matrices:
   - `Upsilon_P` for permutation encryption.
   - `Upsilon_S` for substitution encryption.
5. Partition each image channel and `Upsilon_P` into non-overlapping `b x b` thumbnail blocks.
6. Sort each chaotic block by value to obtain a block-level permutation mapping.
7. Reorder pixels inside each corresponding image block using that mapping, producing the permutation-encrypted image.
8. Convert the auxiliary/non-visual message into a binary bitstream.
9. For histogram-shifting RDH, find a peak point `P` and zero point `Z` in the image/channel histogram.
10. If no zero point exists, choose a minimum-count histogram point, record affected pixel coordinates as overhead, and create a zero point.
11. Store the binary representations of `P` and `Z` in the LSBs of the first 16 pixels in the first row, while recording those original LSBs as overhead.
12. Embed the overhead information plus payload bits using histogram shifting. For `P < Z`, shift values in `(P, Z)` right by 1 and encode each bit at pixels with value `P`.
13. Update the first-row LSBs with `P` and `Z`.
14. Partition `Upsilon_S` into `b x b` blocks and take absolute values to obtain non-negative chaotic values.
15. Pair chaotic values inside each block as `(gamma_1, gamma_2)` and calculate `delta = floor((gamma_1 + gamma_2) * theta)`.
16. Pair pixels inside each corresponding thumbnail block as `tau = (tau_1, tau_2)`.
17. Convert each pixel pair to its sum-preserving index `eta` using Eq. (7).
18. Encrypt `eta` by modular addition with `delta` using Eq. (8), where the modulus is the size of the same-sum pair set from Eq. (9).
19. Convert encrypted index `eta_e` back to an encrypted two-pixel group using Eq. (10).
20. Recombine channels to obtain the final encrypted marked image.

## 3. Complete Decryption and Recovery Pipeline

1. Regenerate the same chaotic matrices `Upsilon_S` and `Upsilon_P` from the same parameters/key material and image identifier.
2. Partition `Upsilon_S` and the encrypted marked image into matching `b x b` blocks.
3. Recreate each pairwise `delta` from chaotic pairs using Eq. (6).
4. For each encrypted pixel pair, compute its sum `s_tau` and convert the pair to encrypted index `eta_e` using Eq. (7).
5. Reverse the modular addition from Eq. (8) to recover `eta`.
6. Convert `eta` back to a pixel pair with the inverse same-sum mapping from Eq. (10)'s structure.
7. After all pairs are processed, obtain the image state immediately after RDH embedding and before substitution encryption.
8. Read the first 16 first-row LSBs and decode them into `P` and `Z` as two 8-bit values.
9. Scan the image row by row, skipping the first-row LSB storage area, and extract bits:
   - For `P < Z`: value `P` extracts `0`; value `P + 1` extracts `1`.
   - For `P > Z`: value `P` extracts `0`; value `P - 1` extracts `1`.
10. Use extracted overhead to restore the original LSBs of the first 16 pixels.
11. Recover the histogram-shifted image by shifting values between `P` and `Z` back by one gray level.
12. Use extracted overhead coordinates, if present, to restore pixels changed when a minimum-count point was used as a pseudo-zero point.
13. Recreate the permutation mapping from `Upsilon_P`.
14. Apply inverse block permutation to recover the original image.

Paper detail not fully specified: The paper describes substitution decryption conceptually but does not provide a numbered decryption equation. The modular inverse `eta = (eta_e - delta) mod |Theta_sum(s_tau)|` is the direct inverse of Eq. (8), so this project uses it as the algebraic inverse of the substitution step.

## 4. Section/Equation Implementation Table

This table maps paper concepts to the project implementation where available. Rows marked as validation-only or not implemented show where the project differs from a complete reproduction of every paper detail.

| Paper section/equation | What it does | Inputs | Outputs | Current Python function/module |
|---|---|---|---|---|
| Sec. 3.1 | Defines sum-preserving encryption over vectors with fixed sum | Pixel vector `tau`, max value `d`, sum `S` | Same-sum encrypted vector | Two-pixel specialization in `src/substitution.py` |
| Sec. 3.2.1 / Eq. (1) | Embeds one bit by changing a peak-point pixel after histogram shifting | Pixel `M(i,j)`, peak `P`, bit `b` | Marked pixel `M'(i,j)` | `src/rdh.py::embed_bits` |
| Sec. 3.2.2 | Extracts bits and reverses histogram shifting | Marked image/channel, `P`, `Z`, overhead | Extracted bitstream, recovered image/channel | `src/rdh.py::extract_bits_and_recover` |
| Sec. 4.1 / Eq. (2) | Cubic map used as a basis for 2D-CSM | `x_n`, `r_1` | `x_{n+1}` | `src/chaos.py::cubic_map` |
| Sec. 4.1 / Eq. (3) | Sinusoidal map used as a basis for 2D-CSM | `x_n`, `r_2` | `x_{n+1}` | `src/chaos.py::sinusoidal_map` |
| Sec. 4.1 / Eq. (4) | Generates coupled 2D chaotic sequence | `x_n`, `y_n`, `r_1`, `r_2` | `x_{n+1}`, `y_{n+1}` | `src/chaos.py::csm_2d_step`, `generate_2d_csm` |
| Sec. 4.3 / Eq. (5) | Computes Lyapunov exponents for chaotic-system analysis | Iterated states, Jacobian eigenvalues | LE values | Not included; chaos visualization only in `experiments/plot_chaos.py` |
| Sec. 5.1 | Builds chaotic matrices for encryption | Image shape `M x N`, explicit demo parameters, explicit `discard_count` | `Upsilon_P`, `Upsilon_S` | `src/chaos.py::generate_upsilon_matrices` |
| Sec. 5.2 | Performs block-wise permutation encryption | Image channels, `Upsilon_P`, block size `b` | Permutation-encrypted image | `src/permutation.py::permute_image_blocks` |
| Sec. 5.3 | Embeds non-visual information in permutation-encrypted image | Permuted image, payload bits | Marked image, overhead | `src/rdh.py` |
| Sec. 5.4 / Eq. (6) | Converts chaotic value pairs into substitution offsets | `gamma_1`, `gamma_2`, `theta` | `delta` | `src/substitution.py::chaotic_pair_delta` |
| Sec. 5.4 / Eq. (7) | Maps a two-pixel same-sum pair to an index | `tau_1`, `tau_2`, `s_tau`, `d` | `eta` | `src/substitution.py::pair_to_index` |
| Sec. 5.4 / Eq. (8) | Encrypts same-sum index by modular offset | `eta`, `delta`, `|Theta_sum(s_tau)|` | `eta_e` | `src/substitution.py::encrypt_pair` |
| Sec. 5.4 / Eq. (9) | Counts valid two-pixel pairs having the same sum | `s_tau`, `d` | same-sum set size | `src/substitution.py::same_sum_pair_count` |
| Sec. 5.4 / Eq. (10) | Converts encrypted index back into a same-sum pixel pair | `eta_e`, `s_tau`, `d` | encrypted pair `tau_e` | `src/substitution.py::index_to_pair` |
| Sec. 5.5 | Reverses substitution, extracts data, recovers image, reverses permutation | Encrypted marked image, explicit parameters | Payload, original image | `src/pipeline.py::decrypt_rgb_image` |
| Sec. 6.2 | Measures recovery quality with PSNR and SSIM | Original image, recovered image | PSNR, SSIM | `experiments/run_section6_experiments.py::recovery_quality` |
| Sec. 6.7 / Eqs. (11)-(14) | Computes adjacent-pixel correlation | Sampled adjacent pixel pairs | Correlation coefficient | Validation helper in `experiments/run_section6_experiments.py` |
| Sec. 6.8 / Eqs. (15)-(17) | Computes NPCR and UACI for differential attack analysis | Two ciphertext images | NPCR, UACI | Validation helper in `experiments/run_section6_experiments.py` |

## 5. Important Parameters Used by the Authors

| Parameter | Meaning | Value or range in paper |
|---|---|---|
| `d` | Maximum 8-bit pixel value in SPE message space | `255` |
| `n` | Vector length in general SPE definition | General `n`; substitution uses two-pixel groups |
| `M x N` | Image/channel dimensions | Experiments use `512 x 512` PNG images |
| `b` | Thumbnail block size | Figures/tables discuss `8, 16, 32, 64, 128, 512`; default recommendation is `32` for privacy against face detection |
| `x_0`, `y_0` | Initial 2D-CSM state | `0.3`, `0.2` in Sec. 5.1 and chaos analysis |
| `r_1`, `r_2` | 2D-CSM control parameters | `50`, `50` in Sec. 5.1 examples; `[1, 100]` explored in chaotic analysis |
| `kappa_1` | Number of transient chaotic values discarded | Named but not numerically specified |
| `kappa_2` | Dynamic additional discard count generated from image identifier `T` | Named but not numerically specified |
| `T` | Unique image identifier used to diversify chaotic sequences | Conversion method not specified |
| `T_tau` | Positive integer converted from `T` | Conversion method not specified |
| `theta` / `vartheta` | Amplification coefficient for chaotic pair offset | Described as predefined and much greater than 1; no value specified |
| `P` | Histogram peak point | Selected per histogram |
| `Z` | Histogram zero point or minimum-count substitute | Selected per histogram |
| First 16 pixels in first row | LSB storage area for `P` and `Z` | 16 LSBs: 8 bits for `P`, 8 bits for `Z` |
| Key length | Claimed key space | 256 bits |
| Key sensitivity example | Demonstration keys | `11111111`/`0xFF` and `11111110`/`0xFE`, despite key-space claim of 256 bits |
| Adjacent-pixel samples | Correlation analysis sample count | 5,000 adjacent pixel pairs |
| Dataset | Experimental image source | First two subsets of Helen dataset, 1,000 images, converted to PNG `512 x 512` |

## 6. Equations That Need Implementation

1. Eq. (1): histogram-shifting bit embedding at peak point `P`.
2. Eq. (2): Cubic map.
3. Eq. (3): Sinusoidal map.
4. Eq. (4): proposed 2D-CSM coupled chaotic map.
5. Eq. (5): Lyapunov exponent calculation for chaos analysis.
6. Eq. (6): chaotic pair amplification offset `delta`.
7. Eq. (7): same-sum pixel-pair-to-index mapping.
8. Eq. (8): index encryption by modular addition.
9. Eq. (9): count of same-sum two-pixel vectors.
10. Eq. (10): index-to-same-sum-pixel-pair mapping.
11. Eq. (11): mean for adjacent-pixel correlation.
12. Eq. (12): variance-like term for adjacent-pixel correlation.
13. Eq. (13): covariance for adjacent-pixel correlation.
14. Eq. (14): adjacent-pixel correlation coefficient.
15. Eq. (15): NPCR.
16. Eq. (16): UACI.
17. Eq. (17): binary difference matrix for NPCR.

## 7. Equation Categories

| Category | Equations |
|---|---|
| Chaotic sequence generation | Eq. (2), Eq. (3), Eq. (4) |
| Chaotic-system analysis | Eq. (5) |
| Permutation | No numbered equation; Sec. 5.2 describes block sorting of `Upsilon_P` and reordering image pixels |
| RDH | Eq. (1), plus Sec. 3.2.2 and Sec. 5.3 prose for extraction, recovery, overhead, and first-row LSB storage |
| Substitution | Eq. (6), Eq. (7), Eq. (8), Eq. (9), Eq. (10) |
| Decryption/recovery | No separate numbered equations; Sec. 5.5 describes inverse substitution, RDH extraction/recovery, and inverse permutation |
| Experiments/security metrics | Eq. (11), Eq. (12), Eq. (13), Eq. (14), Eq. (15), Eq. (16), Eq. (17) |

## 8. Ambiguities and Underspecified Details

Paper detail not fully specified: The paper says the scheme uses a 256-bit key and that the key seeds the chaotic system, but Sec. 5.1 initializes `x_0 = 0.3`, `y_0 = 0.2`, and `r_1 = r_2 = 50`. It does not specify how a 256-bit key is converted into chaotic initial conditions or parameters.

Paper detail not fully specified: `kappa_1` is introduced as the transient discard length but no numeric value or rule for choosing it is provided.

Paper detail not fully specified: The unique image identifier `T` is introduced, but the paper does not define how `T` is chosen, stored, transmitted, or regenerated during decryption.

Paper detail not fully specified: `T` is converted to a positive integer `T_tau`, but the conversion method is not specified.

Paper detail not fully specified: The output after `kappa_1 + T_tau` chaotic iterations is converted to integer `kappa_2`, but the exact conversion, scaling, modulo, and whether `x`, `y`, or both are used is not specified.

Paper detail not fully specified: The paper says two independent chaotic matrices are generated, but it does not fully specify whether `Upsilon_P` and `Upsilon_S` come directly from the `x` and `y` sequences, from separate runs, or from another split of the generated sequence.

Paper detail not fully specified: The permutation step says chaotic block elements are reordered by value to generate `Upsilon_P'`, but it does not specify sorting direction, tie handling, or exact source-to-destination mapping convention.

Paper detail not fully specified: The paper's experiments use image sizes and block sizes that divide evenly, but it does not specify how to handle arbitrary image dimensions or incomplete edge blocks.

Paper detail not fully specified: Pairing order inside each `b x b` thumbnail block is not explicitly stated for either chaotic pairs or image pixel pairs.

Paper detail not fully specified: The amplification coefficient `theta` is only described as predefined and much greater than 1; no concrete value is provided.

Paper detail not fully specified: The RDH description is written mostly for a grayscale histogram, while later Sec. 6.6 says embedding capacity is processed channel-wise. It does not fully specify whether `P`, `Z`, first-row LSB storage, overhead, and payload segmentation are independent per RGB channel.

Paper detail not fully specified: If no zero point exists, the paper says to record coordinates `(i, j)` of minimum-point pixels and re-encode them as overhead, but it does not specify the binary encoding format, coordinate order, length fields, or how many coordinates are stored.

Paper detail not fully specified: The payload and overhead are embedded together, but the paper does not define a payload length header, end marker, or parsing format needed to separate user payload from overhead during extraction.

Paper detail not fully specified: The first 16 first-row LSBs store `P` and `Z`, and their original LSBs become overhead. The paper does not specify whether those 16 pixels are excluded from histogram shifting and payload embedding before the final LSB update.

Paper detail not fully specified: Sec. 5.5 describes recovery by decrementing `x in (P, Z]`, which only matches the `P < Z` case. The exact inverse range for `P > Z` is not written in the proposed-scheme recovery section.

Paper detail not fully specified: Algorithm 1 is embedded as an image in the Springer HTML. The surrounding prose describes the substitution algorithm, but if the image contains extra pseudocode details, those details are not available from the accessible text view used here.

Paper detail not fully specified: Sec. 6.8 says TPE is applied to each block while altering one pixel value within each block to yield two encrypted images, but it does not specify the exact pixel alteration pattern, channel, or payload conditions used for the reported NPCR/UACI table.

Paper detail not fully specified: The paper reports timing on a specific i9-13900HX/32GB platform but does not specify Python/MATLAB/C++ implementation language, library versions, threading, or IO inclusion.

## 9. Minimum Experiments to Reproduce First

1. Lossless recovery check: encrypt, embed, decrypt, extract, and verify recovered image equals original exactly; expected PSNR is infinity and SSIM is 1.
2. Thumbnail preservation check: compare block sums before encryption and after final encrypted marked image for each `b x b` block.
3. Visual block-size comparison: generate encrypted marked images for `b = 8, 16, 32, 64, 128, 512` on a small set of `512 x 512` PNG images.
4. Embedding capacity case study: calculate peak-point capacity per RGB channel and pure capacity after overhead for several representative images.
5. Runtime measurement: report encryption plus embedding time and decryption plus recovery time for selected block sizes.
6. Correlation analysis: sample 5,000 adjacent pixel pairs in horizontal, vertical, and diagonal directions before and after encryption.
7. Differential attack metrics: calculate NPCR and UACI between ciphertexts generated from slightly different plaintexts.
8. Key sensitivity visualization: encrypt the same image using two minimally different keys once the key-to-chaos ambiguity is resolved.

## 10. Recommended Implementation Order

1. Implement and unit-test two-pixel SPE mappings: Eq. (7), Eq. (9), Eq. (10), plus algebraic inverse of Eq. (8).
2. Implement and unit-test the 2D-CSM iterator from Eq. (4) using fixed paper parameters, separate from any key-handling decisions.
3. Implement block partitioning helpers with strict validation that image dimensions are divisible by `b`.
4. Implement permutation and inverse permutation for one grayscale/channel matrix, with tests proving exact reversibility and block-sum preservation.
5. Implement substitution and inverse substitution for one channel using supplied chaotic matrices and chosen `theta`, only after the `theta` ambiguity is resolved.
6. Implement RDH embedding and extraction for one grayscale/channel matrix, first for the fully specified `P < Z` case.
7. Add explicit overhead serialization only after deciding how to handle the paper's missing format.
8. Compose the full RGB encryption/decryption pipeline.
9. Add lossless end-to-end tests and thumbnail-block-sum tests.
10. Add experiment scripts for quality, capacity, timing, correlation, and differential attack metrics.

## Background Topics Studied

1. Thumbnail-preserving encryption and why preserving block sums preserves coarse thumbnails.
2. Format-preserving and sum-preserving encryption for bounded integer vectors.
3. How the paper's two-pixel same-sum indexing works when the sum is below or above 255.
4. Chaotic maps, transient effects, initial conditions, and why deterministic chaos can generate encryption control sequences.
5. Histogram-shifting reversible data hiding, including peak points, zero points, overflow/underflow, and recovery overhead.
6. How RGB channel-wise image processing differs from grayscale processing.
7. Modular arithmetic and how modular addition is reversed during decryption.
8. Image-quality and security metrics: PSNR, SSIM, adjacent-pixel correlation, NPCR, and UACI.
9. Reproducibility discipline: separating paper-stated facts from implementation assumptions.
10. Unit testing reversible algorithms with exact array equality, not just visual inspection.
