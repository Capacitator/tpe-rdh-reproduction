# Audit of the authenticated-TPE project

Scope: the code, reports, NIST scripts, manifests and raw outputs of the
authenticated-TPE work — the prototype in
`tpe_rdh_reproduction/src/authenticated_tpe.py`, its experiment
`experiments/run_authenticated_tpe.py`, the earlier NIST experiment
`experiments/run_nist_sp800_22.py` with `output/nist_sp800_22/`, and the Word
report `authenticated_tpe_latest_old_format.docx` (its Table 7 is the "last
table" of the original document).

This audit changes no existing report, output or result; everything new lives
under `authenticated_tpe_nist_v2/`.

Each finding states whether it is a **defect** (something that is wrong and is
fixed), a **test-design error** (a correct cipher evaluated with the wrong
input), or a **non-issue** (checked and found sound). Nothing here was tuned to
raise p-values: the encryption parameters, block size, key schedule, traversal
orders and tag length are unchanged, apart from the two documented
correctness fixes below.

---

## Summary

| # | Item | Verdict | Effect on NIST p-values |
|---|---|---|---|
| A1 | Definition of the "encryption output" fed to NIST | **test-design error** (fixed) | dominant cause of the published failures |
| A2 | Plaintext/recovered images treated as random streams | **test-design error** (fixed) | removed from randomness claims |
| A3 | `pair_shift` modulo reduction | **defect, negligible** (fixed) | none measurable |
| A4 | `block_r1` modulo reduction | **non-issue** | none |
| A5 | `HMAC_DRBG` (HMAC-SHA256) construction | **non-issue** | none |
| A6 | Counter reuse / domain separation | **non-issue** (verified) | none |
| A7 | Repeated inputs and repeated streams in the old experiment | **defect in the experiment** (fixed) | affects independence of streams |
| A8 | Bit packing and byte order | **non-issue, but undocumented** (documented) | none |
| A9 | NPCR / UACI methodology in the old report | **defect in the metrics** (recomputed) | not a NIST input |
| A10 | Group-mode capacity: whole-image fallback | **method property** (disclosed) | none |
| A11 | Official NIST STS 2.1.2 build defect in the FFT test | **defect in the tool** (fixed) | report could not be produced at all |
| A12 | NPCR/UACI ideals are unreachable for a TPE ciphertext | **method property** (disclosed) | not a NIST input |
| A13 | The tag does not bind image identity | **design property** (disclosed) | not a NIST input |
| A14 | Random Excursions is not applicable to roughly a third of `n = 10^6` streams | **official-suite property** (disclosed) | reduces the applicable sample only |
| A15 | Sum-class size uniformity screening | **checked, no residual bias** | none |
| A16 | Encrypted-image PSNR reference | **measurement-label defect** (corrected) | 27.77 dB was marking-only, not input-to-ciphertext fidelity |

---

## A1. The definition of the encryption output fed to NIST — test-design error

**Finding.** The last table of the old report (`Table 7`) evaluates two input
categories, *"Step-2 intermediate"* and *"Final marked image"*, with 100
streams each, and reports catastrophic outcomes — for example `Frequency`,
`BlockFrequency`, `Runs`, `LongestRun`, `Rank`, `FFT`, `OverlappingTemplate`,
`Universal`, `ApproximateEntropy` all at `0P/100F` with second-level
`p ≈ 6.19e-188`, and `1741P/13059F` / `1839P/12961F` for the 148
non-overlapping templates.

Those two categories are **image byte streams**: the encrypted image after the
Step-2 substitution, and the final RCM-marked image. The authenticated design is
a *thumbnail-preserving* encryption: Step 1 is a permutation inside each
per-sum class, so every adjacent pair sum and therefore every `32 × 32` block
sum is preserved by construction, and the marked image additionally carries the
256-bit tags in the least-significant bits. A TPE ciphertext is *designed* to
retain the spatial structure of the plaintext at block granularity. It is
therefore not a pseudorandom bit string, and no legitimate randomness test can
pass on it. The same file also shows the signature of this: the "ciphertext"
correlation coefficients in `Table 5` remain `0.46…0.86`.

The earlier repository experiment `experiments/run_nist_sp800_22.py` has the
same problem in a different form: its categories are `chaotic` (the `Upsilon_P`
and `Upsilon_S` matrices from the 2-D chaotic map, quantised with
`floor((x+1)*128)`) and `ciphertext` (image bytes). Its own preserved summary
records `{'pass': 484, 'fail': 1292, 'not-applicable': 104}` for `chaotic` and
`{'pass': 410, 'fail': 1210, 'not-applicable': 260}` for `ciphertext`.

**Why this is a test-design error, not a cipher break.** The cryptographic
material of the authenticated scheme is HMAC-SHA256: `Ktpe`/`Kr1`/`Kstruct`
derive from the UserKey, the Step-1 rotation offset comes from
`HMAC-SHA256(Ktpe, …)`, the Step-2 `r1` comes from `HMAC-SHA256(Kr1, …)`, the
group permutation comes from HMAC_DRBG(HMAC-SHA256), and the authentication code
is HMAC-SHA256. Those are the objects whose randomness the scheme relies on, and
they are the only objects for which a NIST SP 800-22 evaluation is meaningful.
The quantised chaotic matrices play no role in the authenticated construction.

**Fix.** The corrected protocol separates the streams:

* cryptographic-component streams — `hmac_drbg`, `pair_shift`, `block_r1`,
  `auth_tag` (100 streams each, 1,000,000 bits each);
* image diagnostics — `ciphertext_diag` (the actual encrypted/marked images) and
  `recovered_diag` (the recovered/decrypted images, i.e. plaintext), reported as
  diagnostics with no randomness claim;
* `reduced_shift_diag` — the actual reduced Step-1 offsets packed as bytes,
  included to make the class-size structure explicit (see A3).

## A2. Plaintext/recovered images must not be treated as ideal random streams

**Finding.** The recovered image is the exact plaintext; for a natural
photograph, an all-zeros image or a flat image it is maximally structured. Any
table that places it in the same column as a keystream invites the reading that
"the encryption failed". The corrected protocol keeps `recovered_diag` in a
separately labelled diagnostics block and states explicitly that a TPE
ciphertext and a recovered plaintext are not randomness claims.

## A3. `pair_shift` modulo reduction — genuine but negligible bias, fixed

**Finding.** The audited prototype computes the Step-1 rotation offset as

```python
word = int.from_bytes(HMAC_SHA256(Ktpe, msg)[:4], "big")
return word % class_size
```

`word` is uniform over `2^32` values, and `class_size = |class of the pair|` is
between 1 and 256. For every class size in that range `2^32 mod class_size` is
small, so the maximum deviation of any output from `1/class_size` is at most
`255 / 2^32 ≈ 5.9e-8`; the worst relative deviation (class size 255) is about
`1 / 16.8 million`. With 1,000,000 samples per stream this bias is not
detectable by NIST SP 800-22 or by any test in this protocol.

**Fix (revision `atpe-v2.1`).** `atpe_v2.pair_shift` uses rejection sampling:
draw the primary word; if `word >= floor(2^32 / class_size) * class_size`, draw
again from a domain-separated retry message `msg || b"\x01retry" || u16(attempt)`.
The result is exactly uniform over the class.

**Backward compatibility (verified, not claimed).** Every value the old code
produced is reproduced bit-for-bit unless the primary draw falls in the
rejection set, i.e. with probability at most `2^-24` (about `6e-8`) per
reduction. This is checked empirically in
`tests/test_atpe_v2.py::test_revised_reduction_agrees_with_the_audited_reduction`
(20,000 random reductions, zero disagreements) and analytically by the bound in
`v2.activation_status()`. The revision is therefore a correctness hardening, and
— stated plainly — it **cannot** be the reason for any p-value difference. It is
included because the audit asked for genuine reductions of bias, not because it
improves results.

**Related, and not a defect.** The *reduced* offsets are uniform inside each sum
class, but the classes have different sizes (1…256), so a byte-packing of the
offsets is not uniform over `0..255` — e.g. a class of size 2 can only emit
values 0 and 1. That is a property of sum-class sizes inherent to
thumbnail-preserving encryption, not a weakness of the keystream.
`output/metrics/class_uniformity.csv` records a chi-square test that the reduced
offset is uniform *within* every class, and `reduced_shift_diag` shows what a
byte-packed version of those offsets does in the NIST suite.

## A4. `block_r1` modulo reduction — no bias

**Finding.** `block_r1` returns `BE32(digest[:4]) % 4`. Because `2^32` is an
exact multiple of 4, the reduction is exactly uniform; no rejection sampling is
needed and none was added. (`tests/test_atpe_v2.py::
test_block_r1_reduction_is_bias_free_by_construction`.) The same holds for the
`mod len(values)` rotation index in Step 1, which is a permutation position
rather than a modulo reduction.

## A5. `HMAC_DRBG` construction — sound

**Finding.** `HMACDRBG` initialises `K = 0x00…00` (32 bytes) and `V = 0x01…01`,
then calls `HMAC_DRBG_Update(entropy∥nonce∥personalization)`; `generate4` performs
`V = HMAC(K, V)`, returns `V[0:4]`, then `HMAC_DRBG_Update(None)`. This matches
SP 800-90A Rev. 1 `HMAC_DRBG_Instantiate` (which does use the two-step update)
and `HMAC_DRBG_Generate` for a 4-byte request. There is no missing update, no
skipped final update, and no state reuse between calls.

**Evidence.** The paper's published permutation prefix
`(224, 3, 167, 218, 229, 171, 106, 172)` and the full-permutation digest
`55f272be5c1686f05a22714dba3a2651d79cb11d14df3d66ba715d3e38ba8c38` are reproduced
by an independent reference implementation inside the existing test suite, and
the DRBG first outputs `0x833513C6, 0xB64F37E2, 0x37299C7D, 0x7E60D678` are
reproduced by the revised build.

One documented deviation from the SP 800-90A *interface* (not from its
algorithm): the method consumes the DRBG in 4-byte Generate calls, so 28 bytes of
each `V` are discarded and an update happens after every 4 bytes. That is the
paper's usage, and each 4-byte block is still an HMAC_DRBG output; the corrected
protocol preserves this behaviour exactly.

## A6. Counter reuse and domain separation — verified clean

**Finding.** Every derivation uses a fixed-width, domain-separated message:

| Derivation | Message | Domain size |
|---|---|---|
| Step-1 offset | `"tpe-shift" ∥ ImageID(16) ∥ bid_u16be ∥ k_u16be` | 256 × 512 = 393,216 per key/ID |
| Step-2 `r1` | `"r1" ∥ bid_u16be` | 256 per key |
| group key | `ImageID ∥ channel_u8 ∥ Bid0..3_u16be` | ordered, so block order matters |
| image key | `"image" ∥ ImageID` | one per ID |

`(bid, k)` is injective over the block, no two derivations in one image share a
message, and the ImageID is bound into the Step-1 message, so two different
images never share a keystream position. Checks:
`tests/test_atpe_v2.py::test_derivation_domains_never_repeat_a_message`.

**What the old experiment did wrong here** is a separate matter — see A7.

**New in the corrected protocol**: the UserKey/ImageID index space is partitioned
across categories and streams (3,100 disjoint indices, `KEY_RANGES` in
`src/streams.py`), so no `(key, message)` pair is repeated anywhere in the
700-stream campaign, and the generated streams are asserted to be pairwise
distinct by SHA-256 (`output/independence_checks.json`).

## A7. Repeated inputs and repeated streams in the earlier experiment — defect

**Finding.** `experiments/run_nist_sp800_22.py` used only **10** streams per
category and built them as

```python
IMAGE_NAMES = ["airplane","baboon","couple","girl","lena","peppers",
               "airplane","baboon","couple","girl"]
KEYS = [BASE_KEY, BASE_KEY] + [sha256(f"tpe-rdh-nist-key-{i}") for i in range(2, 10)]
```

so four images appear twice and streams 1 and 2 share the identical key. Ten
streams are also far below the 100 streams NIST needs for a meaningful
second-level uniformity test (the suite prints `----` for the uniformity column
in that run). Re-using one key for two streams while the ImageID differs is not
fatal for the TPE keystream, but the design does not state or enforce
independence.

**Fix.** The corrected protocol uses 100 streams per category, one disjoint
`(UserKey, ImageID)` instance per stream (or a documented set of disjoint
instances where a single instance cannot supply 1,000,000 bits — `block_r1` and
`auth_tag`), no repeated image inside a stream, no repeated image *selection*
between the two image-diagnostic categories, and explicit verification that all
700 streams are pairwise distinct.

## A8. Bit packing and byte order — sound, now documented

**Finding.** The old script packed `uint8` image bytes MSB-first with
`f"{byte:08b}"`, row-major. That is a legitimate and consistent convention; the
failure came from *what* was packed (A1), not from *how*.

**Fix.** `streams.stream_ascii` implements exactly the same MSB-first expansion,
and the corrected protocol documents it, records the SHA-256 of both the binary
stream and its 1,000,000-character ASCII expansion for every stream, and asserts
the expansion has length 1,000,000 and contains only `0`/`1`.

## A9. NPCR / UACI methodology in the old report — defect in the metrics

**Finding.** The old report's `Table 3` publishes `NPCR ≈ 1.09 %` and
`UACI ≈ 0.0088 %`. The standard definitions compare **two ciphertexts of the same
plaintext** and have ideal values `99.6094 %` and `33.4635 %`; a correctly
computed NPCR cannot be ≈1 %. The published pair is consistent instead with the
*embedding distortion* between a marked image and its own Step-2 intermediate
(only RCM carrier LSBs change), i.e. a different quantity under a standard name.
(The repository's own differential metrics for the chaotic pipeline, which do
compare plaintext with ciphertext after a one-pixel perturbation, report
96–99 % NPCR — so the 1.09 % figure is not comparable even within the project.)

**Fix.** `experiments/run_metrics.py` now reports the standard two-ciphertext
NPCR/UACI (same plaintext, two independent `(UserKey, ImageID)` instances) with
the ideal values stated, and additionally reports the `marked_vs_step2` and
`plaintext_vs_marked` quantities *under their own names and with an explicit
note*, so the old numbers can be traced without being mistaken for NPCR/UACI.

## A10. Group-mode capacity and whole-image fallback — method property

**Finding.** Group mode must reach 256 net bits (`#T + #O − #N`) in *every* group
of four blocks. For several of the 100 distinct test images this is not
achievable, and the design then discards the provisional group marks and embeds
one whole-image tag instead. This is the method's documented all-or-nothing
behaviour, not an implementation error, but it means some ciphertexts are
whole-image-mode.

**Fix (disclosure only).** The corrected protocol records the mode and pair usage
per image in `output/stream_manifest.csv` and reports the mode distribution, so
that no ciphertext is silently presented as group-mode.

## A11. Official NIST STS 2.1.2 build defect — defect in the tool, fixed

**Finding.** With the unmodified official source, `assess` never writes
`experiments/AlgorithmTesting/finalAnalysisReport.txt` (the file is created but
left empty) and aborts. Diagnosed with AddressSanitizer:

```
==3142==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 8
    #0 DiscreteFourierTransform src/discreteFourierTransform.c:42
0x... is located 0 bytes after 8,000,000-byte region
allocated by ... DiscreteFourierTransform src/discreteFourierTransform.c:21
```

`m[i+1] = sqrt(X[2i+1]**2 + X[2i+2]**2)` for `i = n/2 − 1` reads `X[n]`, one
element past a workspace allocated for `n` doubles; the same routine allocates
`wsave` with `2*n` doubles although the FFTPACK-style routines it calls need
`2*n + 15`. The read only fills `m[n/2]`, which the confidence-interval loop
never consumes, so the published statistic is unaffected — but the abort
prevents the report from being written.

**Fix.** Two allocation sizes in `discreteFourierTransform.c`
(`calloc(n+2, …)`, `calloc(2*n+16, …)`), recorded in
`/home/ubuntu/work/sts/sts_build.patch` and hashed into every provenance file.
No test statistic, threshold or parameter is changed, and the suite now completes
with `Statistical Testing Complete` and a full `finalAnalysisReport.txt`.

---
## A12. NPCR/UACI diffusion ideals are unreachable for a TPE ciphertext — method property

**Finding.** The standard NPCR/UACI compare two ciphertexts of the *same*
plaintext and have ideal values 99.6094 % and 33.4635 %. Measured correctly, the
authenticated scheme gives 91.48 % and 8.16 %. That is not a weakness of the key
schedule: a thumbnail-preserving ciphertext **preserves every adjacent pair
sum** by construction, so two ciphertexts of one plaintext can differ only by a
rotation inside each sum class, which bounds the per-pixel difference. The
diffusion ideals do not apply to this cipher class, and no parameter may be
changed to reach them without destroying the thumbnail-preserving property.

**Fix (disclosure).** `experiments/run_metrics.py` reports the measured values
together with the ideal values and an explicit statement that the ideals are
unreachable here, instead of presenting a diffusion number that cannot apply.

## A13. The authentication tag does not bind image identity — design property

**Finding.** `AuthTag_c = HMAC(Kgroup_c, M_c)` authenticates the ciphertext
blocks of the group; `ImageID` enters through the key derivation. A ciphertext
of a *different* image produced under the same UserKey and the same ImageID
therefore verifies, and its plaintext is released. This is not a forgery — the
tag is correct for the content it authenticates — but it means the scheme does
not bind an image to its identifier, so reusing an ImageID for two images is a
real operational hazard (exactly as the prototype's own documentation states).

**Fix (disclosure).** The behaviour is reported as an accepted substitution in
`output/metrics/tamper_results.csv` and in the new report, instead of being
listed as a rejected attack. All five genuine forgery / wrong-credential cases
are rejected with no plaintext released, and that is reported separately.

## A14. Random Excursions applicability at n = 10^6 — official-suite property

**Finding.** The suite applies the Random Excursions (Variant) test only to
streams containing at least 500 cycles. At `n = 10^6` the expected cycle count is
`≈ 800` with standard deviation `≈ 600`, so 31–44 of the 100 genuine random
streams per cryptographic category are reported *not applicable*, and all 100 of
the image-derived streams are, because structured bits cycle far less. The
original document's Table 7 shows `N/A` for both tests for the same reason.

**Fix (disclosure).** Not-applicable outcomes are counted and reported per
category in `summary_counts.csv`, listed in `parse_warnings.txt`, and excluded
from pass proportions exactly as the official report does — never silently
counted as passes.

## A15. Sum-class size uniformity screening — checked, no residual bias

**Finding.** The hypothesis "the reduced offset is uniform" depends only on the
class *size* (1…256), so there are 129 distinct hypotheses, not 1,010 classes.
Testing each class separately inflates the apparent failure count by
multiplicity.

**Fix.** `output/metrics/class_uniformity.csv` tests each distinct size once with
200,000 independent PRF words and applies a Holm–Bonferroni correction over the
family: 2 uncorrected `p < 0.01` against an expectation of 1.28, and **0**
rejections after correction. The two marginal sizes were re-tested with
1,048,576 independent draws (`output/metrics/class_uniformity_retest.csv`) and
are uniform (p = 0.3207 for size 4, 0.1495 for 86, 0.6103 for 142). The
rejection-sampled reduction is therefore confirmed exact, with no detectable
residual bias.

## A16. Encrypted-image PSNR reference — measurement-label defect, corrected

**Finding.** `run_metrics.py` measured `PSNR(marked_image, step2_image)` and the
report labelled it "Encrypted-image PSNR". That compares the final marked
ciphertext with the already transformed Step-2 carrier; it measures the
distortion of authentication-tag embedding only. It is not the input-to-final-
ciphertext image fidelity that the user's concern and that table heading
implied. This reference mismatch explains why a value near 27.77 dB could be
reported while the final image's actual fidelity against the original was lower.

**Correction.** The experiment now separately calculates the two valid,
explicitly named pairs:

* `input_vs_encrypted_psnr_db` / `input_vs_encrypted_ssim`: original input versus
  final encrypted/marked output;
* `marking_distortion_psnr_db` / `marking_distortion_ssim`: final marked output
  versus the Step-2 carrier immediately before tag embedding.

On the Baboon fixture the rerun gives input-to-final PSNR **17.2877 dB**, SSIM
**0.4941**, while marking-only distortion is **27.7176 dB**, SSIM **0.9629**.
The output confirms why the comparison references must not be interchanged. The
cipher algorithm, keys, identifiers, parameters and image inputs did not change;
this is a metric/reference correction, not score tuning. Exact decryption and
authentication still pass on all six UCT images.

The supplied paper PDF and the user's referenced example image were not present
in the active workspace. The corrected report therefore fixes the standard
input-vs-final-output measure without claiming that the missing paper's precise
fixture or preprocessing has been reproduced. See `FIDELITY_CORRECTION.md`.

## What was *not* changed

* block size (32), image size (512×512 RGB), pairs per block (512), blocks per
  channel (256), group size (4), tag length (256 bits);
* the key schedule and every domain label;
* the Step-1 class construction, the Step-2 mapping, the RCM T/O/N encoding, the
  group permutation, the embedding traversal order, the tag placement;
* `α = 0.01`, NIST test parameters (all STS 2.1.2 defaults), and the number and
  length of streams;
* every previously published result, report and output file.

## Honest statement about the outcome

The audit found one genuine cryptographic defect (`pair_shift` modulo bias) and
one genuine tool defect (the STS FFT overflow). The first is provably
inconsequential at the sample sizes used, and the second blocked the official
report from being produced at all. **Neither explains, nor improves, the
published failures.** The published failures came from evaluating structured
image bytes against a randomness test.

With the corrected stream definitions the cryptographic components pass at the
theoretical rate — 98.77 % to 98.99 % of first-level p-values above α = 0.01,
against a theoretical 99 %, and 0/188, 2/188, 2/188 and 3/188 second-level
components failing uniformity against an expectation of 1.88 — while the
image-derived diagnostics fail heavily (1.36 %, 8.27 % and 2.90 % pass) and are
reported in full, per component, with p-values, pass/fail counts and the
not-applicable outcomes. No stream was removed, no identifier was altered, no
failure was dropped, and no parameter was changed to raise a p-value. The
revision that *was* made is a real correctness fix that provably cannot move any
p-value, and the original document is preserved unchanged next to the new report.
