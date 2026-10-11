# Exact-order authenticated 32×32 block-TPE results

**Run date:** 11 October 2026  
**Branch:** `audit/flowchart-exact-order-auth`  
**Scope:** six fixed UCT color images; 32×32 blocks; revised authentication order and reversible block-sum compensation.

## Executive result

- The flowchart-aligned component sequence now runs **after the completed legacy TPE/RDH ciphertext**: reversible authentication Step-1 and Step-2 → HMAC_DRBG four-block group selection → per-group HMAC-SHA256 → RCM tag embedding.
- All **864 of 864** per-channel/four-block tags pass preflight and verification. Each 256-bit tag has at least **1,150 net RCM bits** available; there is no whole-image fallback.
- All six images and their embedded RDH payloads recover **exactly**. A changed pixel was rejected and localized to the affected group (see `tamper_checks.csv` and the unit test).
- The final authenticated ciphertext preserves the **pre-authentication TPE block sum exactly** for every 32×32 block and color channel. Thus the final original-to-ciphertext thumbnail PSNR equals the pre-authentication TPE thumbnail PSNR, measured directly from the actual final output.

## Per-image measurements

| Image | Four-block tags | Minimum group capacity (bits) | Full RGB PSNR, original→final (dB) | 32×32 thumbnail PSNR, original→final (dB) | Thumbnail SSIM | Max auth-vs-base block-sum delta | Exact image + payload recovery |
|---|---:|---:|---:|---:|---:|---:|---|
| Airplane | 192 | 1,496 | 12.13 | 54.02 | 0.999879 | 0 | Yes |
| Baboon | 192 | 1,552 | 10.92 | 52.20 | 0.999952 | 0 | Yes |
| Couple | 48 | 1,150 | 15.83 | 54.43 | 0.999812 | 0 | Yes |
| Girl | 48 | 1,292 | 13.31 | 54.84 | 0.999922 | 0 | Yes |
| Lena | 192 | 1,462 | 11.78 | 51.16 | 0.999893 | 0 | Yes |
| Peppers | 192 | 1,482 | 11.70 | 49.82 | 0.999928 | 0 | Yes |
| **Mean** | — | — | **12.61** | **52.75** | **0.999898** | **0** | **6/6** |

### What the two PSNR numbers mean

- **Full RGB PSNR (mean 12.61 dB)** compares every original RGB pixel with the corresponding final encrypted RGB pixel. It is expected to be low because this output is encrypted; it is not a thumbnail-preservation score.
- **32×32 thumbnail PSNR (mean 52.75 dB)** compares the rounded RGB means of each corresponding 32×32 block in the original and final encrypted image. This is the relevant thumbnail metric for the TPE output. Its range is **49.82–54.84 dB**.
- Thumbnail SSIM is calculated over the corresponding 8×8 RGB block-mean images. It ranges from **0.999812 to 0.999952**.
- The final authenticated image is compared directly to the original; values are not inferred from another stage. The final block sums equal the base TPE block sums exactly, so the authentication layer does not change the measured thumbnail relative to the base TPE stage.

## What changed from the previous hybrid

| | Previous hybrid (kept intact) | Exact-order compensated version |
|---|---|---|
| Ordering | RCM/authentication was wrapped before the legacy substitution. | Authentication Step-1/Step-2 and HMAC/RCM operate on the completed legacy TPE ciphertext. |
| Group authentication | All six test images fell back to one whole-image tag; no four-block localization. | All 864 expected group tags are used; no fallback. |
| Thumbnail PSNR | Prior final range: 36.46–51.47 dB. | Final range: 49.82–54.84 dB; exact preservation of each pre-auth TPE block sum. |
| Reversibility | Exact image and payload recovery passed. | Exact image and payload recovery still pass; group tampering is localized. |

## Capacity redesign and format limitation

The canonical adjacent-pixel pairing on the completed TPE ciphertext had negative RCM net capacity in every four-block group. To make the flowchart’s post-TPE RCM stage feasible without changing tag size or reporting a favorable subset, this prototype defines a stable ascending-value **logical pairing layout within each 32×32 block**. Pixels do not move between blocks or change their displayed coordinates; the layout only defines which values form RCM pairs. The map is data-dependent, so it is carried in an encrypted/authenticated ChaCha20-Poly1305 sidecar and also covered by each group HMAC.

The Step-2 transform and RCM marking can shift block sums. A reversible per-pixel correction map in the same protected sidecar restores the post-auth block sums to the pre-authentication TPE values. Verification first removes this correction, extracts and verifies all tags, and only then reverses the authentication transforms and legacy TPE.

This has a material cost: the required sidecars are approximately **1.19–1.20 MB** for 512×512 images and **0.29 MB** for 256×256 images. The encrypted image alone is not a complete ciphertext container; the sidecar is required for authentication and recovery. A compact single-file format remains future work.

## Validation and scope

- `pytest -q`: **26 passed**, with one expected divide-by-zero warning in an existing exact-equality PSNR test.
- All six fixed real-image runs: authentication accepted, exact RGB recovery, and payload recovery passed.
- All 864 group capacities were audited individually in `group_capacity_audit.csv`; all are ≥256 bits.
- The previous Word report and previous hybrid output were not overwritten. The uncompensated exact-order diagnostic run is also preserved separately.
- **No new NIST STS run was made for this flowchart/layout/compensation wrapper.** Previously reported NIST results remain results for their defined cryptographic-component streams; they must not be described as NIST validation of this new end-to-end layout.

## Reproduction

From this project directory:

```bash
python3 -m pip install -r requirements-exact-order.txt
python3 experiments/run_flowchart_exact_order.py
pytest -q
python3 experiments/create_exact_order_report.py
```

The experiment script fixes the six-image corpus, `b=32`, test keys/payload and ImageID derivation, writes all six image triptychs, the complete per-group capacity CSV, metrics CSV, encrypted sidecars, and SHA-256 manifest. The keys are public reproducibility fixtures, **not production secrets**.

## Deliverables in this folder

- `professor_32x32_block_effect_gallery_exact_flowchart.docx` — new visual report; prior document preserved.
- `metrics.csv` — six complete metric rows.
- `group_capacity_audit.csv` — all 864 group-capacity records.
- `tamper_checks.csv` — selected tamper/localization checks.
- `*_original.png`, `*_block32_tpe.png`, `*_block32_authenticated_exact.png` — actual images from each run.
- `*_layout.sidecar` — protected reversible layout/correction metadata required by the protocol.
- `SHA256SUMS.txt` — final artifact/code/test hashes.
