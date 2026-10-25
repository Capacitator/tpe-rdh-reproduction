# Four pixel TPE authentication v3 audit

Starting branch head: `32e6c4922c1fc624a0f3878294663ff97d6b35ef`. This version preserves the previous reports and outputs.

## Corpus and integrity

The original 512×512 RGB arrays for all six UCT-named fixtures are present in the committed `authenticated_tpe_nist_v2/output/metrics/visual_gallery/` directory. Their per-array SHA-256 values match the reconstruction manifest. Four run source PNG file hashes match the tracked originals exactly; Couple and Girl run file bytes are not recoverable, although the 512×512 RGB arrays match. The upstream download/licence record is absent; no new source images have been redistributed beyond the existing repository assets. See `input_manifest.json` for original and recovered hashes, pixel hashes, and provenance limits. Run the repository helper `python3 authenticated_tpe_nist_v2/scripts/prepare_four_pixel_inputs.py` to restore expected filenames. It re-encodes PNG files and verifies RGB arrays.

## Key limitation

The v2 experiment used two random 32-byte keys supplied only through environment variables. Their values were never retained in the outputs or repository. The saved bundle artifacts therefore cannot now be independently decrypted unless those original keys exist in an external secret store. A new run with new keys verifies only that new run. Never commit keys. The four-pixel API now rejects an omitted key; keep keys in a secret manager or protected environment injection.

## Metrics

`recomputed_image_metrics.csv` is recomputed from the tracked source references and saved four-pixel ciphertext PNGs. Full image MSE/PSNR compare every uint8 RGB sample of the original 512×512 image and its authenticated ciphertext PNG: MSE = mean((I-C)^2), PSNR = 10 log10(255²/MSE). Thumbnail MSE compares per-channel block means arranged as a 16×16×3 array, each cell averaged from one non-overlapping 32×32 RGB image block. All six thumbnail MSE values are zero. The 5-bit user payload is the only demonstrated payload. Combined bundle bytes are encrypted PNG + sidecar. The prior recorded timings mixed encryption, export, and recovery; no encryption-only runtime is claimed.

## NIST evidence

The two checked-in summary reports and local scratch workspace were inspected. Both reports are NIST STS 2.1.2 runs over 100 ASCII bitstreams of 1,000,000 bits, using the 15 standard test families; `RandomExcursions` and `RandomExcursionsVariant` rows are conditional on each stream having enough cycles. STS parameters visible in the assessment logs: Block Frequency M=128, Non-overlapping Template m=9, Overlapping Template m=9, Approximate Entropy m=10, Serial m=16, Linear Complexity M=500. Per-instance rows include multiple template/cycle-dependent instances. Recomputed counts and complete test-family lists are in `nist_independent_recount.json`. Input files, logs, and manifests are retained here for audit, but generator source, exact stream-generation seeds/parameters, and a complete invocation script are missing. These are exploratory schedule-stream diagnostics, not a compliant execution of the predeclared v2 protocol; they do not establish cryptographic security.

## Adaptation and scope

The paper's four-pixel sum-preserving transform is used as a reversible pixel-block operation. The code adapts the repository's 2D-CSM output into the paper's key domain and does not reproduce the paper's own key schedule. The image permutation, 32×32 grouping, histogram-shifting RDH tags and five-bit user payload, RCM authentication grouping, HMAC-SHA256, and AEAD sidecar are repository additions. RDH/HMAC tags, RCM group layout, and sidecar corrections are not paper-defined four-pixel operations. The experiments show implementation behavior only, not a security proof.

## Tamper localization

One-pixel edit: Lena coordinate (y=135,x=361), green channel; four-block group [75, 226, 253, 185]. Cross-image splice shown in `airplane_to_lena_channel_group_map.png`: Airplane block 5 replaced Lena block 5 at y=0,x=160, size 32×32. Failed groups per channel are R [83,221,43,5], G [15,202,236,5], B [5,169,84,134]. A group identifies four blocks, not the exact altered block or pixel.

