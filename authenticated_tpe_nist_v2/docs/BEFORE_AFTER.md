# Before / after

Everything below comes from artifacts in `output/`: `before_after.csv`,
`headline_counts.csv`, `nist_per_test_summary.csv`, every category's
`first_level_pvalues.csv`, `second_level_uniformity.csv`, `summary_counts.csv`
and the raw official reports under `output/nist_raw/`. The "before" numbers are
transcribed from Table 7 of the original Word document (`authenticated_tpe_latest_old_format.docx`,
column *Step-2 intermediate*), which is preserved unchanged.

**Supplemental correction (2026-10-11):** a review found that the earlier v2
report called a Step-2-to-marked-image comparison "encrypted-image PSNR". That
is tag-marking distortion, not input-to-final-ciphertext image fidelity. The
correct original-input-to-final-encrypted/marked metrics and exact Baboon
comparison are in [`FIDELITY_CORRECTION.md`](FIDELITY_CORRECTION.md) and the
separate corrected Word report. The earlier v2 report is preserved as an audit
artifact; do not cite its mislabeled Table 1 as input-to-ciphertext fidelity.

## Headline

| | Before (original Table 7) | After (this revision) |
|---|---|---|
| Objects evaluated | Step-2 intermediate image bytes and final marked image bytes | HMAC_DRBG(HMAC-SHA256), Step-1 pair-shift PRF, Step-2 block-r1 PRF, HMAC-SHA256 authentication tags |
| Streams per category | 100 | 100 |
| Bits per stream | 1,000,000 | 1,000,000 |
| Stream independence | 4 of 10 images reused, one key shared by two streams (in the repository's own 10-stream script) | 700 pairwise-distinct streams, 3,100 disjoint key/ImageID instances, no image repeated inside a stream |
| Typical `Frequency` outcome | `0P/100F`, uniformity p = 6.19e-188 | `99P/1F` … `100P/0F`, p = 0.475 … 0.964 |
| `Runs`, `LongestRun`, `Rank`, `FFT`, `OverlappingTemplate`, `Universal`, `ApproximateEntropy`, `Serial`, `CumulativeSums` | all `0P/100F` or `0P/200F`, p ≈ 6.19e-188 | 96–100 % pass, p = 0.019 … 0.998 |
| `RandomExcursions` / `Variant` | `N/A` | 534P/2F and 1202P/4F over the applicable streams |
| Overall first-level outcomes | ~13,472 pass / 25,600 fail in the two image columns | cryptographic components: 98.8–99.0 % pass; diagnostics: 1.4–8.3 % pass (disclosed) |

The second-level uniformity p-value of `6.19e-188` that fills the old table is not an arbitrary
number: it is exactly `gammainc(9/2, 450/2) = 6.186801032394592e-188`, the value the suite produces
when **all 100 first-level p-values fall into a single histogram bin**. The corrected run reproduces
that same value for the image-derived diagnostic streams
(`output/categories/*_diag/second_level_uniformity.csv`, full precision `6.186801e-188`), which is
direct confirmation that the old table was evaluating structured image bytes.

## Per-test comparison, characteristic results (HMAC_DRBG category)

| Test | Before: Step-2 intermediate | After: HMAC_DRBG | After: uniformity p-values |
|---|---|---|---|
| Frequency | 0P/100F | 99P/1F | 0.475 |
| Block Frequency | 0P/100F | 100P/0F | 0.109 |
| Runs | 0P/100F | 99P/1F | 0.720 |
| Longest Run of Ones | 0P/100F | 99P/1F | 0.851 |
| Binary Matrix Rank | 0P/100F | 97P/3F | 0.575 |
| Discrete Fourier Transform | 0P/100F | 99P/1F | 0.103 |
| Non-overlapping Template (148) | 1741P/13059F | 14646P/154F | 0.00204 – 0.991 |
| Overlapping Template | 0P/100F | 96P/4F | 0.956 |
| Maurer's Universal | 0P/100F | 100P/0F | 0.514 |
| Approximate Entropy | 0P/100F | 98P/2F | 0.998 |
| Serial (2) | 0P/200F | 194P/6F | 0.202 – 0.319 |
| Cumulative Sums (2) | 0P/200F | 198P/2F | 0.182 – 0.350 |
| Linear Complexity | 97P/3F | 97P/3F | 0.019 |
| Random Excursions (8) | N/A | 534P/2F | 0.187 – 0.756 |
| Random Excursions Variant (18) | N/A | 1202P/4F | 0.00457 – 0.620 |

`after_uniformity_p_range` for multi-component tests is the full range over components; the
complete per-component values are in `output/nist_per_test_summary.csv` and
`output/categories/hmac_drbg/second_level_uniformity.csv`.

## All seven categories

| Category | Kind | Pass | Fail | N/A | Pass rate | Second-level components failing uniformity |
|---|---|---|---|---|---|---|
| `hmac_drbg` | cryptographic component | 17,758 | 184 | 858 | 98.97 % | 3 / 188 |
| `pair_shift` | cryptographic component | 17,811 | 183 | 806 | 98.98 % | 2 / 188 |
| `block_r1` | cryptographic component | 17,684 | 180 | 936 | 98.99 % | 0 / 188 |
| `auth_tag` | cryptographic component | 17,439 | 217 | 1,144 | 98.77 % | 2 / 188 |
| `reduced_shift_diag` | diagnostic | 220 | 15,980 | 2,600 | 1.36 % | 162 / 188 |
| `ciphertext_diag` | diagnostic | 1,339 | 14,861 | 2,600 | 8.27 % | 162 / 188 |
| `recovered_diag` | diagnostic | 470 | 15,730 | 2,600 | 2.90 % | 162 / 188 |

Interpretation, stated plainly:

* The four cryptographic components behave exactly like the pseudorandom streams
  they are supposed to be. The pass rate is within 0.2 percentage points of the
  theoretical `1 − α = 99 %`, and the number of second-level components failing
  uniformity (0, 2, 2, 3 out of 188) is at the multiple-comparison expectation
  `0.01 × 188 = 1.88`.
* The three diagnostic categories fail heavily, as they must. A TPE ciphertext
  preserves block sums, a recovered image is plaintext, and the byte-packed
  reduced offsets inherit the sum-class size structure. **These failures are
  reported in full and are not hidden or removed.** They are not a defect of the
  keystream, and they are not a randomness claim of the encryption.

## Not-applicable results

Every parse notice in every category is an official Random Excursions or Random
Excursions Variant "not applicable" message — there are no other warnings. The
full list is in each category's `parse_warnings.txt`.

| Category | Streams where Random Excursions was not applicable |
|---|---|
| `hmac_drbg` | 33 / 100 |
| `pair_shift` | 31 / 100 |
| `block_r1` | 36 / 100 |
| `auth_tag` | 44 / 100 |
| `ciphertext_diag`, `recovered_diag`, `reduced_shift_diag` | 100 / 100 |

The suite applies this test only when a stream contains at least 500 cycles; at
`n = 10^6` the expected cycle count is ≈ 800 with a standard deviation of ≈ 600,
so roughly a third of genuine random streams fall below the threshold. The
structured image-derived streams never reach it, which is exactly why the
original document's Table 7 shows `N/A` for both random-excursion tests. The
pass proportions for those two tests are computed over the applicable streams
only, as the official report does.

## Authentication, recovery and differential metrics

| Quantity | Value | Note |
|---|---|---|
| Exact recovery (6 UCT images) | max absolute error 0, PSNR ∞, SSIM 1.0000 | every tag verified |
| Marked-image fidelity vs Step-2 | 27.72 – 32.51 dB, SSIM 0.9763 – 0.9970 | reproduces the original Table 1 (airplane 30.18 dB here vs 30.20 dB in the original) |
| Forgery attempts (bit flip, same-channel block swap, cross-channel block swap) | 5 / 5 rejected, 0 plaintext released | see `output/metrics/tamper_results.csv` |
| Wrong UserKey / wrong ImageID | rejected, 0 plaintext released | |
| Valid ciphertext of another image under the same key and ImageID | **accepted** | disclosed: the tag authenticates ciphertext content and the scheme does not bind image identity, hence the requirement of a fresh ImageID per image |
| NPCR / UACI between two ciphertexts of one plaintext | 91.48 % / 8.16 % | below the diffusion ideals (99.6094 % / 33.4635 %) **by construction**: pair sums are preserved, so the two ciphertexts differ only by rotations inside sum classes |
| The original report's NPCR 1.0944 % / UACI 0.0084 % | not reproducible | not a two-ciphertext NPCR/UACI; the closest reproducible quantities are plaintext-vs-marked (90.99 % / 6.30 %) and marked-vs-Step-2 (12.4–15.3 % / 0.55–1.08 %). The document does not define which one was used, so the corrected definitions are reported instead |

## The revision itself changes no outcome

The only cipher change is the rejection-sampled Step-1 reduction (`atpe-v2.1`).
It is provably inactive except with probability `≤ 255/2^32 ≈ 5.9e-8` per
reduction:

* 200,000 random reductions agree exactly with the audited implementation
  (`tests/test_atpe_v2.py`), and all published vectors (`pair_shift == 19`,
  `block_r1 == 42 → 2`, the DRBG sequence, the permutation digest) are unchanged;
* regenerating all 700 streams in a second independent run reproduced every
  SHA-256 bit for bit (`STREAMS IDENTICAL ACROSS TWO INDEPENDENT RUNS`);
* the class-size uniformity screening (128 distinct sizes, 200,000 words each)
  found 2 uncorrected p < 0.01 against an expectation of 1.28, and 0 after
  Holm–Bonferroni; the marginal sizes were re-tested with 1,048,576 draws and are
  uniform (p = 0.32, 0.15, 0.61 for sizes 4, 86, 142).

**Conclusion of the before/after analysis.** The improvement is not a
parameter change and not a favourable selection: it is a change of *what was
evaluated*. Before, a structured thumbnail-preserving ciphertext was submitted to
a randomness battery, which it cannot pass by design. After, the HMAC-based
components the scheme actually relies on are evaluated, and they pass at the
theoretical rate, while the image-derived streams stay in the report as
diagnostics with their failures shown in full.
