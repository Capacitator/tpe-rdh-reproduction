# Experiment provenance

## Repository and separation

- New isolated Git worktree: `/home/ubuntu/audit/tpe-repo/authenticated_tpe_exact_order`
- Branch: `audit/flowchart-exact-order-auth`
- Parent branch: `audit/flowchart-hybrid-auth`
- The prior `authenticated_tpe_nist_v2` worktree, previous Word reports, previous hybrid output, and NIST data were not edited by this experiment.
- An earlier uncompensated exact-order diagnostic run is preserved in `output/metrics/flowchart_exact_order/`; the final reported run is `output/metrics/flowchart_exact_order_compensated/`.

## Inputs and fixed parameters

- Tested package versions are pinned in `requirements-exact-order.txt` (Python 3.12).
- Input source directory: sibling `tpe_rdh_reproduction/input/uct_colour/`.
- Full fixed corpus: `airplane.tif`, `baboon.tif`, `couple.tif`, `girl.tif`, `lena.tif`, and `peppers.tif`. Each is decoded as RGB at its stored dimensions (512×512, except Couple and Girl at 256×256); none is selected or discarded after seeing results.
- Block size: 32×32. Each color channel is grouped into HMAC_DRBG-permuted sets of four spatial blocks.
- Legacy TPE key fixture and protocol defaults are fixed in `experiments/run_flowchart_exact_order.py`; the script uses the legacy default `vartheta=10000.0` and embeds the fixed 32-byte payload `0123456789ABCDEF0123456789ABCDEF`.
- Authentication key: SHA-256 of the documented public fixture string `public reproducible research authentication key fixture`. These values are reproducibility fixtures, not secret or production keys.
- ImageID: first 16 bytes of `SHA-256(b"flowchart-exact-order-image-id-v2\0" || UTF8(image name) || original RGB bytes)`.
- HMAC tags: HMAC-SHA256, 256 bits per channel/four-block group. HMAC_DRBG uses the project's existing implementation and unbiased Fisher–Yates rejection sampling for group ordering.

## Reversible additions

1. Stable ascending-value rank defines logical pair membership inside each 32×32 ciphertext block; it does not permute pixels across blocks or change displayed coordinates.
2. The per-block logical pairing map is included in the group HMAC and stored in the sidecar.
3. After RCM embedding, a deterministic balanced per-pixel correction restores every block/channel sum to its pre-authentication TPE sum. The signed correction vector and layout map are compressed and encrypted/authenticated together using ChaCha20-Poly1305 under a separately derived key. A fresh 96-bit nonce is used per sidecar.
4. Verification authenticates the sidecar, reverses the correction, extracts and checks all group HMACs, and withholds the TPE ciphertext/plaintext on any failure. Only after every group passes are authentication Step-2, Step-1, and the legacy TPE/RDH pipeline reversed.

Because the matching is data-dependent and the final sum correction is reversible, the sidecar is required. It is intentionally not claimed as a zero-overhead, image-only method.

## Fidelity calculation

- Full RGB PSNR: `skimage.metrics.peak_signal_noise_ratio(original, final_authenticated, data_range=255)` on the complete RGB arrays.
- 32×32 thumbnail: each aligned block/channel mean is rounded to the nearest integer (NumPy `rint`), then the same PSNR function compares all corresponding 8×8 RGB block-mean arrays.
- Thumbnail SSIM: `structural_similarity(..., channel_axis=2, data_range=255)` over those 8×8 RGB block-mean arrays.
- `group_capacity_audit.csv` contains the net RCM capacity for every keyed group, including all groups that pass; no capacity failures are omitted.
- `tamper_checks.csv` records the clean-image check, a real-image pixel tamper localized to group `(channel=1, first block=42)`, a modified-sidecar rejection, and a wrong-ImageID rejection.

## Validation trail

- Main six-image experiment: `experiments/run_flowchart_exact_order.py`.
- Tamper/localization check: `experiments/run_tamper_localization_check.py`.
- Word report generator: `experiments/create_exact_order_report.py`.
- Regression tests: `pytest -q` → 26 passed. One warning comes from an existing test intentionally calculating PSNR for exactly equal arrays (infinite PSNR).
- Existing 700-stream NIST test data and `stream_manifest.csv` were copied from the untouched prior worktree into this isolated worktree solely to run its repository-wide regression suite; those copied fixtures are not new NIST results.
- No NIST STS 2.1.2 campaign was run for this exact-order, data-dependent-layout/compensation version. Do not present earlier component-stream p-values as an end-to-end NIST validation of this new wrapper.

The image pixel hashes, final output hashes, code/test hashes, and per-run values are recorded in `metrics.csv` and `SHA256SUMS.txt`.
