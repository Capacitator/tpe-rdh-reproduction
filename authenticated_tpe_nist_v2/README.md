# authenticated_tpe_nist_v2 — corrected NIST SP 800-22 evaluation

This folder contains the audited revision of the authenticated thumbnail-preserving
encryption (TPE) prototype of `tpe_rdh_reproduction`, together with a complete,
reproducible NIST SP 800-22 Rev. 1a campaign over predefined stream families.

Nothing outside this folder is modified. All previously published code, outputs and
reports are preserved; in particular the original Word report is untouched and the
new report is written to `output/report/`.

## Read first

| Document | Content |
|---|---|
| [`docs/AUDIT.md`](docs/AUDIT.md) | Full audit: every checked item, verdict, evidence and fix. Includes what was **not** changed and an honest statement about the outcome. |
| [`docs/STREAM_DEFINITIONS.md`](docs/STREAM_DEFINITIONS.md) | Exact, reproducible definition of all 700 streams and the independence argument. |
| [`docs/BEFORE_AFTER.md`](docs/BEFORE_AFTER.md) | Before/after comparison, including the failures that remain. |
| [`docs/FIDELITY_CORRECTION.md`](docs/FIDELITY_CORRECTION.md) | Corrected original-input-to-final-ciphertext PSNR/SSIM; explains the earlier reference-image mismatch. |

## Layout

```
src/atpe_v2.py            revised cipher (thin revision layer over the audited prototype)
src/streams.py            predefined stream families, manifests, independence checks
src/nist_runner.py        official assess driver + report parser + uniformity recomputation
experiments/run_protocol.py   the whole campaign (streams -> assess -> CSVs -> provenance)
experiments/run_metrics.py    recovery, input-vs-encrypted fidelity, tag-marking distortion, tamper, same-key, NPCR/UACI, class uniformity
experiments/retest_class_uniformity.py  1,048,576-draw re-test of the marginal class sizes
experiments/summarise_nist.py per-(category,test) aggregation and before/after table
experiments/make_report.py    builds the new Word report in the original format
tests/test_atpe_v2.py         unit tests, including verification of the real artifacts
input/images_512/             106 normalized 512x512 test images (6 UCT + 100 UCID)
output/                       every stream, digest, raw official report and CSV
```

## Results at a glance

| Category | Kind | First-level pass / fail / N-A | Pass rate | Second-level components failing uniformity |
|---|---|---|---|---|
| `hmac_drbg` | cryptographic component | 17,758 / 184 / 858 | 98.97 % | 3 / 188 |
| `pair_shift` | cryptographic component | 17,811 / 183 / 806 | 98.98 % | 2 / 188 |
| `block_r1` | cryptographic component | 17,684 / 180 / 936 | 98.99 % | 0 / 188 |
| `auth_tag` | cryptographic component | 17,439 / 217 / 1,144 | 98.77 % | 2 / 188 |
| `reduced_shift_diag` | diagnostic | 220 / 15,980 / 2,600 | 1.36 % | 162 / 188 |
| `ciphertext_diag` | diagnostic | 1,339 / 14,861 / 2,600 | 8.27 % | 162 / 188 |
| `recovered_diag` | diagnostic | 470 / 15,730 / 2,600 | 2.90 % | 162 / 188 |

The theoretical values for genuine random streams are a 99 % pass rate and
`0.01 × 188 = 1.88` second-level component failures. The image-derived
diagnostics fail heavily, are reported in full, and are explicitly not a
randomness claim of the cipher. The original document's `0P/100F` at
`p = 6.19e-188` is reproduced exactly by those diagnostics.

## Artifacts deliberately not committed to git

`output/streams/*.bin` (85 MB), the ASCII campaign inputs (668 MB, deleted after
the run) and `input/images_512/*.png` (49 MB) are excluded for size. Each is
covered by a SHA-256 in `output/SHA256SUMS.txt`, in `stream_manifest.csv` and in
`image_pool_manifest.csv`, and the deterministic pipeline reproduces every digest
bit for bit — a second independent run of the whole stream generator produced
identical digests, which is recorded in `docs/BEFORE_AFTER.md`.

## What the revision changes

1. **`pair_shift` modulo bias (genuine defect, negligible effect).** The old code dropped
   the Step-1 rotation offset with `word % class_size`, which is biased by at most
   `255 / 2^32 ≈ 5.9e-8`. The revision uses rejection sampling, making the offset exactly
   uniform, and is *bit-identical* to the old code except with probability `≤ 6e-8` per
   draw, so no previously published value or ciphertext changes.
2. **NIST stream definition (the real cause of the published failures).** The old last
   table fed image byte streams — the Step-2 intermediate and the final marked image — to
   the suite. A TPE ciphertext preserves every block sum by construction and can never
   pass a randomness test. The corrected protocol tests the cryptographic components
   (HMAC_DRBG, the Step-1 and Step-2 PRFs, the HMAC authentication tags) and reports the
   image-derived streams separately as diagnostics.
3. **Official STS build defect.** The unmodified STS 2.1.2 aborts and never writes
   `finalAnalysisReport.txt`; two allocation sizes in the FFT test are corrected without
   changing any statistic, and the patch is hashed into the provenance record.
4. **Stream independence.** 100 streams per category instead of 10, one disjoint
   `(UserKey, ImageID)` instance per stream, no repeated image inside a stream, and an
   explicit check that all 700 streams are pairwise distinct by SHA-256.
5. **Correct differential metrics.** NPCR/UACI are computed between two ciphertexts of the
   same plaintext (ideal 99.6094 % / 33.4635 %); the old embedding-distortion quantity is
   still reported, but under its own name.
6. **Correct image-fidelity reference.** Encrypted-image PSNR/SSIM compare the final
   marked ciphertext with the original input. Distortion between final marking and the
   pre-mark Step-2 image remains separately reported, but is not called encrypted-image
   fidelity.

Parameter values — block size, image size, tag length, key schedule, domain labels,
traversal orders, α = 0.01, stream count and stream length — are unchanged.

## Reproduce

```bash
# 1. build the official suite (STS 2.1.2) with the documented build patch
# 2. run the campaign
python3 experiments/run_protocol.py --sts-dir <NIST_STS_2_1_2_ROOT> --parallel 4
python3 experiments/run_metrics.py
python3 experiments/retest_class_uniformity.py
python3 experiments/summarise_nist.py
python3 experiments/make_report.py
python3 -m pytest tests -q
# 3. re-verify every delivered artifact against its recorded digest
python3 experiments/verify_artifacts.py     # -> "RESULT: all checks passed"
```

Regenerating the streams reproduces every SHA-256 in `output/stream_manifest.csv`.
`experiments/run_protocol.py --skip-run` re-runs only the statistical suite on the
already generated streams.

## Scope and honesty

NIST SP 800-22 is a statistical battery, not a security proof, and NIST has announced its
revision while stating it must not be used as an assessment of cryptographic generators.
This work does not claim cryptographic security, does not hide any failure or
not-applicable outcome, did not remove any failing stream, and did not change any
parameter in order to raise a p-value.

## Flowchart hybrid: preserved block effect plus authentication

The separate research prototype combining the legacy 32×32 block-TPE/RDH stage
with HMAC-SHA256, HMAC_DRBG grouping and reversible RCM marking is documented in
[`docs/FLOWCHART_HYBRID.md`](docs/FLOWCHART_HYBRID.md). It explains the reversible
ordering adjustment required by a genuine RCM capacity problem and reports all
six images, both full-pixel and block-thumbnail PSNR/SSIM, exact-recovery tests,
and the whole-image fallback (four-block localization did not pass for this set).

- Code: `src/block32_authenticated_tpe.py`
- Six-image runner: `experiments/run_flowchart_hybrid.py`
- Capacity audit: `experiments/run_capacity_audit.py`
- Tests: `tests/test_block32_authenticated_tpe.py`
- Results/provenance/hashes: `output/metrics/flowchart_hybrid/`
- Updated Word gallery: `output/metrics/block32_corrected_images/professor_32x32_block_effect_gallery.docx`

Reproduce with `python3 experiments/run_flowchart_hybrid.py`,
`python3 experiments/run_capacity_audit.py`, and
`python3 -m pytest tests -q`. The Word generator appends the measured results
without removing the earlier gallery pages.
