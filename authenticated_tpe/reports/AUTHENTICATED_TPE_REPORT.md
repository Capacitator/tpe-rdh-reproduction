# Authenticated TPE: implementation and evaluation report

## Executive findings

This project is a separate prototype of the professor-supplied reversible block-group authentication method. It combines pair-sum-preserving two-pixel encryption, reversible contrast mapping (RCM), and HMAC-SHA256 tags. It is independently implemented and does not import the original chaotic TPE/RDH pipeline.

Checked-in outputs record 6/6 natural UCT clean cases with successful verification and exact recovery, and 7/7 controlled tampering or credential cases rejected without plaintext. A constructed capacity fixture exercises whole-image fallback. These observations cover the recorded cases and are not a formal security proof or independent cryptanalysis.

## Method and scope

The implementation follows the professor-provided *Reversible Block-Group Authentication for Thumbnail-Preserving Encrypted Color Images Using Reversible Contrast Mapping and HMAC-SHA256* (16 pages; SHA-256 `f0348a3435259037f53028830f4d00056f8ad58f4c87843f3766c924b1a1607d`). This is a documented reconstruction with explicit encoding conventions, not a run of the professor's Colab notebook.

Inputs are 512 × 512 RGB uint8 images, divided into 32 × 32 blocks. Each channel has 256 blocks, 512 adjacent horizontal pixel pairs per block, and 64 groups of four blocks. A full 256-bit HMAC-SHA256 tag is embedded per group, yielding 192 group tags across RGB. If any group cannot carry its tag, group marks are discarded and the implementation falls back to one whole-image tag.

The authentication hierarchy derives channel-specific TPE, block-shift and structure keys from the user key; group tags bind the private ImageID, channel and ordered block IDs, and a separate image tag binds the image ID. Group membership is generated deterministically from a key-derived HMAC_DRBG seed. The exact labels and encodings are specified in [`docs/AUTHENTICATED_TPE.md`](../docs/AUTHENTICATED_TPE.md). In production, the private ImageID is generated with the OS CSPRNG and retained by the owner. The API does not keep a registry to enforce uniqueness.

For each adjacent pair, Step 1 applies a key-derived reversible transform that preserves the pair sum. Step 2 cyclically shifts the smaller pixel value within each block using its derived `r1` value. HMAC_DRBG generates a key-dependent permutation of blocks, partitioned into groups of four. RCM embeds each group's full 256-bit HMAC-SHA256 tag; extraction reverses the mapping to recover and verify those tags. If any group cannot hold its tag, all provisional group marks are discarded and the code attempts one whole-image tag. Decryption/recovery is permitted only after the required tag verification succeeds; failed verification returns no plaintext. Exact encodings and RCM boundary conventions are documented in the method notes.

The six source fixtures are shared, read-only inputs at `../tpe_rdh_reproduction/input/uct_colour/`. The couple and girl source files are 256 × 256 and are resized to 512 × 512 by the experiment script; the other four are already 512 × 512. The experiment uses deterministic public test keys and IDs, which are not production secrets.

## Clean-image authentication results

| Image | Mode | Tags | Verified | Exact recovery | Pairs used | Marked vs Step-2 PSNR (dB) | Protect (s) | Verify (s) |
|---|---|---|---|---|---|---|---|---|
| airplane | group | 192 | True | True | 54314 | 30.200616 | 2.829163 | 3.179332 |
| baboon | group | 192 | True | True | 57326 | 27.708603 | 2.893875 | 3.142060 |
| couple | group | 192 | True | True | 80498 | 32.585125 | 2.998788 | 3.442145 |
| girl | group | 192 | True | True | 61936 | 30.054280 | 2.869511 | 3.300352 |
| lena | group | 192 | True | True | 54926 | 28.046331 | 2.826731 | 3.117933 |
| peppers | group | 192 | True | True | 57430 | 28.999219 | 2.875899 | 3.166885 |
| constructed_capacity_fallback_fixture | whole-image | 1 | True | True | 268 | 50.359641 | 2.417387 | 3.224808 |

The checked-in CSV contains 7 clean cases; 7/7 verify and recover exactly. These include the six UCT image cases; modes, tag counts, exact per-image values and timings above are read directly from `output/clean_authentication_results.csv`. Marked-image PSNR compares the marked image with the Step-2 image before RCM marking and is not a security metric.

## Tampering and authentication failures

| Attack | Rejected | Failed groups | Plaintext released |
|---|---|---|---|
| single_pixel_lsb_flip | True | 1 | False |
| same_channel_block_swap | True | 2 | False |
| cross_channel_block_swap | True | 2 | False |
| wrong_user_key | True | 0 | False |
| wrong_image_id | True | 0 | False |
| different_protected_image_replacement | True | 0 | False |
| single_pixel_lsb_flip_whole_image_mode | True | 0 | False |

The artifact records 7/7 attacks rejected and 7/7 with no plaintext released. Wrong-key, wrong-ImageID, replacement, same-channel block-swap, and cross-channel block-swap outcomes and failed-group counts are shown in the CSV-derived table. Group localization is only reported where verification identifies affected groups; zero means no failed group was attributable in these cases.

## Capacity and operating modes

| Fixture | Mode | Groups at target | Minimum group peak (bits) | Whole-image capacity (bits) |
|---|---|---|---|---|
| airplane | group | 192 | 1619 | 356142 |
| baboon | group | 192 | 1225 | 337798 |
| couple | group | 192 | 333 | 269366 |
| girl | group | 192 | 652 | 324672 |
| lena | group | 192 | 1392 | 353508 |
| peppers | group | 192 | 1216 | 338340 |
| constructed_capacity_fallback_fixture | whole-image | 189 | 0 | 368912 |

For the 6 group-mode natural-image cases, minimum group peak capacity ranges from 333 to 1619 bits; whole-image net capacity ranges from 269366 to 356142 bits. The separate constructed fixture exercises whole-image fallback: 189 groups meet the group threshold, and its whole-image capacity is 368912 bits. Capacity details are in `output/capacity_results.csv`.

## Tests, independent check, and provenance

Authenticated-project test command `python -m pytest tests -q` from `authenticated_tpe/` passed **28 passed in 82.23s (0:01:22)**. The independent script `python experiments/check_authenticated_tpe_tampering.py` exited successfully; recorded output: `independent_clean_group_mode=PASS; independent_clean_exact_recovery=PASS; independent_single_bit_tamper_rejected=True; independent_failed_groups=1; independent_no_plaintext_on_tamper=PASS; independent_wrong_key_rejected=PASS; independent_wrong_image_id_rejected=PASS`.

### Artifact provenance

- Branch `authenticated-tpe-paper`; report source commit `aee62653f1e0a6fdea34eff382492b3a7338cd5e`; worktree at report generation: `dirty`.
- Artifact-generating source commit: `e004bda185b10c5c0a91061e3715e8c3a0248f6b`; artifact source worktree state: `clean (recorded at run start, before regenerating output files)`.
- Runtime: Python 3.11.0; NumPy 2.4.4; Pillow 12.0.0; pytest 8.4.2.
- Input paths: `../tpe_rdh_reproduction/input/uct_colour/{airplane,baboon,couple,girl,lena,peppers}.tif` (read-only shared UCT fixtures).
- Input image SHA-256 values:

  - `airplane.tif`: `515d0a5105047916be9faed513330046be41a61f4b155e854731e512ce1f4c4a`
  - `baboon.tif`: `cd4456f2562dc352acee627428eb4e2ccaed5f53082ce0838d9fff6b8a3e3517`
  - `couple.tif`: `e1760e29f10762fe60349e2848b01065b69784d04848606dd8644b6a9a893288`
  - `girl.tif`: `d044fcfbea02123efdc167e596f45e839c39c2e1ca2ff841710ef4db15bc4dfb`
  - `lena.tif`: `d5cd280e7e970a31828fe2c91ead6c8ce3ea257d04b6eabbd8e254c6e1cce255`
  - `peppers.tif`: `208e8c6542e91a1b3d7d9457626b7577fc0d21affeb800435858cc83f2537649`
- Specification SHA-256: `f0348a3435259037f53028830f4d00056f8ad58f4c87843f3766c924b1a1607d`.
- Public deterministic test fixtures only; no secret key or private production ImageID is reproduced here.
- Report-generation script: `authenticated_tpe/experiments/generate_authenticated_report.py`; exact command: `.venv/bin/python authenticated_tpe/experiments/generate_authenticated_report.py` from repository root.
- Source/artifact paths: `authenticated_tpe/src/`, `tests/`, `experiments/`, `docs/`, and `output/`; measurements are from `output/clean_authentication_results.csv`, `tamper_results.csv`, `capacity_results.csv`, and `provenance.txt`.
- Statistical experiment provenance and script hashes: `authenticated_tpe/output/statistical_provenance.txt` and `authenticated_tpe/output/nist_sp800_22/provenance.txt`.

## Reproduction status and limitations

The implementation reconstructs the paper description using explicit documented conventions. The professor's external notebook and full attack study were unavailable. The reported six UCT fixtures, constructed fallback fixture, finite attack set, authenticated-TPE statistical and differential evaluation, and NIST SP 800-22 diagnostics are prototype evaluation, not a formal security proof or independent cryptanalysis. Lossless image handling, UserKey secrecy, and fresh private production ImageIDs remain operational requirements.

## Authenticated-TPE statistical and differential evaluation

### Plaintext-difference NPCR/UACI (fixed ImageID)

For each of the six UCT images, protect the clean input and its modified copy under the same public test UserKey and fixed deterministic test ImageID. Modify only the top-left R-channel sample in each 32×32 block by +1, or −1 if it is 255, matching the original project's differential perturbation convention at the authenticated method's specified block size. Both outputs must authenticate and recover exactly. Per-channel R/G/B and pooled RGB rows are recorded per image and for the six-image aggregate.

Formulas: NPCR = 100 × count(Aᵢ ≠ Bᵢ) / N; UACI = 100 × Σ|int16(Aᵢ)−int16(Bᵢ)| / (255 × N). For a channel N=H×W; for pooled RGB N=3×H×W. These follow the original project's per-channel formulas and pooled RGB key-sensitivity formula.

| Experiment | Image | Channel | NPCR % | UACI % | Base exact | Modified exact |
|---|---|---|---|---|---|---|
| plaintext_difference_fixed_image_id | airplane | R | 3.28330994 | 0.02526676 | True | True |
| plaintext_difference_fixed_image_id | airplane | G | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | airplane | B | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | airplane | RGB | 1.09443665 | 0.00842225 | True | True |
| plaintext_difference_fixed_image_id | baboon | R | 3.31611633 | 0.02983243 | True | True |
| plaintext_difference_fixed_image_id | baboon | G | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | baboon | B | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | baboon | RGB | 1.10537211 | 0.00994414 | True | True |
| plaintext_difference_fixed_image_id | couple | R | 3.32908630 | 0.01954172 | True | True |
| plaintext_difference_fixed_image_id | couple | G | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | couple | B | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | couple | RGB | 1.10969543 | 0.00651391 | True | True |
| plaintext_difference_fixed_image_id | girl | R | 3.25737000 | 0.02385158 | True | True |
| plaintext_difference_fixed_image_id | girl | G | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | girl | B | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | girl | RGB | 1.08579000 | 0.00795053 | True | True |
| plaintext_difference_fixed_image_id | lena | R | 3.26232910 | 0.02818687 | True | True |
| plaintext_difference_fixed_image_id | lena | G | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | lena | B | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | lena | RGB | 1.08744303 | 0.00939562 | True | True |
| plaintext_difference_fixed_image_id | peppers | R | 3.33480835 | 0.03090354 | True | True |
| plaintext_difference_fixed_image_id | peppers | G | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | peppers | B | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | peppers | RGB | 1.11160278 | 0.01030118 | True | True |
| plaintext_difference_fixed_image_id | aggregate_six_images | R | 3.29717000 | 0.02626382 | True | True |
| plaintext_difference_fixed_image_id | aggregate_six_images | G | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | aggregate_six_images | B | 0.00000000 | 0.00000000 | True | True |
| plaintext_difference_fixed_image_id | aggregate_six_images | RGB | 1.09905667 | 0.00875461 | True | True |

### One-bit key sensitivity (fixed ImageID)

Keep the same image, fixed ImageID and payload-free setup; flip one bit by XORing byte 0 of the UserKey with 0x01, matching the original project's key-sensitivity convention. Both outputs must authenticate and recover under their corresponding keys.

| Experiment | Image | Channel | NPCR % | UACI % | Base exact | Flipped key exact |
|---|---|---|---|---|---|---|
| one_bit_key_sensitivity_fixed_image_id | airplane | R | 97.59750366 | 9.24443114 | True | True |
| one_bit_key_sensitivity_fixed_image_id | airplane | G | 97.32055664 | 9.34283687 | True | True |
| one_bit_key_sensitivity_fixed_image_id | airplane | B | 97.43576050 | 9.08593870 | True | True |
| one_bit_key_sensitivity_fixed_image_id | airplane | RGB | 97.45127360 | 9.22440223 | True | True |
| one_bit_key_sensitivity_fixed_image_id | baboon | R | 97.47200012 | 11.26700757 | True | True |
| one_bit_key_sensitivity_fixed_image_id | baboon | G | 98.20556641 | 10.82322663 | True | True |
| one_bit_key_sensitivity_fixed_image_id | baboon | B | 97.54409790 | 10.26944030 | True | True |
| one_bit_key_sensitivity_fixed_image_id | baboon | RGB | 97.74055481 | 10.78655816 | True | True |
| one_bit_key_sensitivity_fixed_image_id | couple | R | 87.17994690 | 4.90461761 | True | True |
| one_bit_key_sensitivity_fixed_image_id | couple | G | 86.25221252 | 3.71369455 | True | True |
| one_bit_key_sensitivity_fixed_image_id | couple | B | 86.09580994 | 3.38168275 | True | True |
| one_bit_key_sensitivity_fixed_image_id | couple | RGB | 86.50932312 | 3.99999830 | True | True |
| one_bit_key_sensitivity_fixed_image_id | girl | R | 96.67167664 | 7.71721933 | True | True |
| one_bit_key_sensitivity_fixed_image_id | girl | G | 91.26319885 | 5.79328350 | True | True |
| one_bit_key_sensitivity_fixed_image_id | girl | B | 90.50102234 | 5.20418354 | True | True |
| one_bit_key_sensitivity_fixed_image_id | girl | RGB | 92.81196594 | 6.23822879 | True | True |
| one_bit_key_sensitivity_fixed_image_id | lena | R | 96.68884277 | 10.06405101 | True | True |
| one_bit_key_sensitivity_fixed_image_id | lena | G | 97.48115540 | 9.28854250 | True | True |
| one_bit_key_sensitivity_fixed_image_id | lena | B | 98.37455750 | 10.38583045 | True | True |
| one_bit_key_sensitivity_fixed_image_id | lena | RGB | 97.51485189 | 9.91280799 | True | True |
| one_bit_key_sensitivity_fixed_image_id | peppers | R | 98.17276001 | 10.33653858 | True | True |
| one_bit_key_sensitivity_fixed_image_id | peppers | G | 92.27142334 | 7.86662382 | True | True |
| one_bit_key_sensitivity_fixed_image_id | peppers | B | 92.76504517 | 6.96348901 | True | True |
| one_bit_key_sensitivity_fixed_image_id | peppers | RGB | 94.40307617 | 8.38888380 | True | True |
| one_bit_key_sensitivity_fixed_image_id | aggregate_six_images | R | 95.63045502 | 8.92231087 | True | True |
| one_bit_key_sensitivity_fixed_image_id | aggregate_six_images | G | 93.79901886 | 7.80470131 | True | True |
| one_bit_key_sensitivity_fixed_image_id | aggregate_six_images | B | 93.78604889 | 7.54842746 | True | True |
| one_bit_key_sensitivity_fixed_image_id | aggregate_six_images | RGB | 94.40517426 | 8.09181321 | True | True |

NPCR and UACI are empirical differential metrics, not proofs of cryptographic security. CSVs and test conditions: `authenticated_tpe/output/npcr_uaci_results.csv`, `key_sensitivity_npcr_uaci.csv`, and `statistical_provenance.txt`.

### Same-key/different-image behavior

The fixed-ImageID variant holds key and ImageID constant for airplane and baboon, isolating image dependence. The separate image-specific deterministic-ID variant follows the paper's private ImageID model; because both image and ImageID change, that variant alone cannot establish image dependence. Only ImageID digests are shown.

| Variant | Image | Image file SHA-256 | ImageID SHA-256 | Step-1 SHA-256 | Step-2 SHA-256 | Final SHA-256 | Image differs | ID differs | Step 1 differs | Step 2 differs | Final differs | Exact recovery |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fixed_image_id_isolates_image_dependence | airplane | 515d0a5105047916be9faed513330046be41a61f4b155e854731e512ce1f4c4a | 35fad5784126a5377fd10f743335e52d2833e93d23d80fa78a5ce05421a42618 | c7ef78fc25a8c2df2ad3290cb22d836200c7f5172e93fabf46f2888cacc32fc2 | 4d88eb946ddc6fe316769afaddfee97f4436c4de171ab7afec6ecc65dec53451 | 498939fe12ab2713e7ca696826b11aa03efe919c19211a445875e70da110de71 | True | False | True | True | True | True |
| fixed_image_id_isolates_image_dependence | baboon | cd4456f2562dc352acee627428eb4e2ccaed5f53082ce0838d9fff6b8a3e3517 | 35fad5784126a5377fd10f743335e52d2833e93d23d80fa78a5ce05421a42618 | b359b551b713532019241a17bf4dac165acd332f3b6d7e91abf3eb7180a0e93f | f21fec1f58003342fc48167d5780ca4c50b3e9a761d29e6a0fe953aac5934629 | 8283e9d2b81050beb514a8b72936db772d1873bdcc585f7fb09c2e40aa2f3473 | True | False | True | True | True | True |
| image_specific_deterministic_ids_follow_private_id_model | airplane | 515d0a5105047916be9faed513330046be41a61f4b155e854731e512ce1f4c4a | 7cda682262d9a8a78c56c977594b0d23320f97b2fca2cf55f53a9991630c98f4 | 8cdac1cfb5431eb0d93854013e298928a0c8d63648876776c7ad1b4c1da0eea4 | cfc53de553f3a1fc554d11222cd232b5f785f2dafd48b4f865a49b3ed460f84f | c8c82c5ea86b39dbc37e6e8ec723bbd5e46d7783123b168e814238207b2fce2b | True | True | True | True | True | True |
| image_specific_deterministic_ids_follow_private_id_model | baboon | cd4456f2562dc352acee627428eb4e2ccaed5f53082ce0838d9fff6b8a3e3517 | df1862b0a1b8d37a44c204a7b0f57ed3bce8a7dbdff7f1c629dea54aae1a436e | 32dadb1785af8190f0aa73141fd90472f2dfe50d103a4dd2d697242b2dd42956 | 78b8d9339684b9bbfc548cf6971f7248fe49daab8607f099d2b57d647c8a83ec | 1d53215cea1c46e93d4b761a6e6268604bd98c00d393ebd0e7dd21a02de877f1 | True | True | True | True | True | True |

### Same-image consistency and hashes

| Case | Image | ImageID SHA-256 | Step-1 SHA-256 | Step-2 SHA-256 | Final marked SHA-256 | Recovered SHA-256 | Repeat identical | Different ID changes output | ID absent from marked pixels | Exact recovery |
|---|---|---|---|---|---|---|---|---|---|---|
| same_image_same_key_same_id | airplane | 35fad5784126a5377fd10f743335e52d2833e93d23d80fa78a5ce05421a42618 | c7ef78fc25a8c2df2ad3290cb22d836200c7f5172e93fabf46f2888cacc32fc2 | 4d88eb946ddc6fe316769afaddfee97f4436c4de171ab7afec6ecc65dec53451 | 498939fe12ab2713e7ca696826b11aa03efe919c19211a445875e70da110de71 | a7405a85dc79ba2207e04c2544d55b6fce0eb29e9293768db1aee663bee44e35 | True | True | True | True |
| same_image_same_key_same_id | baboon | 35fad5784126a5377fd10f743335e52d2833e93d23d80fa78a5ce05421a42618 | b359b551b713532019241a17bf4dac165acd332f3b6d7e91abf3eb7180a0e93f | f21fec1f58003342fc48167d5780ca4c50b3e9a761d29e6a0fe953aac5934629 | 8283e9d2b81050beb514a8b72936db772d1873bdcc585f7fb09c2e40aa2f3473 | a511e253857a0bfd85137d3b35d6f4e6140b0c3288ca8d56f1f5c39aff59e694 | True | True | True | True |
| same_image_same_key_same_id | couple | 35fad5784126a5377fd10f743335e52d2833e93d23d80fa78a5ce05421a42618 | 887e8908643e593167abcc4969225999c389c719a9bba384fc300353fbd430e3 | 7d926f5d71a3a76fc6b047b914399ab2803fbf170bb1f40b37051ed4c06bb4c1 | 6b4e646afbfb48d04b8ef8c2bbadb5b22fb281777fc26261f5bffbd5fb8c8176 | 9f9ad1112f91344bfb0fa1fb6bbbbf63b7470f39e250f975e2586dc3f0cdff97 | True | True | True | True |
| same_image_same_key_same_id | girl | 35fad5784126a5377fd10f743335e52d2833e93d23d80fa78a5ce05421a42618 | 671710185e90649c25fa3c64ac3354db343cef1a13443cbb9a5963e4bbe6d2ec | 236f63649bec36cc292a5869acf1ffc11343d9169047d03b593fd6d1ad556005 | 1355229e5703bb0444707915810b39d87457add92a62d51f1c79a06a473987f5 | a9b54310f3477ac2060d80f1d6de6af596706916c1057ded797a72369b29236e | True | True | True | True |
| same_image_same_key_same_id | lena | 35fad5784126a5377fd10f743335e52d2833e93d23d80fa78a5ce05421a42618 | a714816ce2529e279492802d1fa432938417e3be99e69a4d4fff75af113686dc | 0f2e7c296067b6262986ca636a94165d5e7217be495f8b3b483758ec547820ba | 002f205b87903d854d9d91f1202c3fba489e7402d7aaf16f379d9c7d8dcd865d | c878c0dc0b46bd7a13d0d183467b74752165e39c7b86f627666ad637da6be500 | True | True | True | True |
| same_image_same_key_same_id | peppers | 35fad5784126a5377fd10f743335e52d2833e93d23d80fa78a5ce05421a42618 | d08c8aa94c28d42f737d6a8ea70ac4fc0061c745d21726411a6c721716a60e19 | 59f6fb18b32827fd678d18c88af7cce594504db172eb7d03c437f33bd2253676 | 6ecd525e43918d6eed6ec97d10ef3db937ad71186dff392de534eaa2bb95efc8 | 5350521bbe3522935ed1f87e43532fafb679f5fea3419de13695a2e4da63ba46 | True | True | True | True |

### NIST SP 800-22 Rev. 1a

The official STS 2.1.2 workflow and parameters match the original project's stream count, length, alpha, image order, key fixtures, packing, selected tests, special settings, and pass/fail/not-applicable interpretation. Category `step2_intermediate` is the keyed Step-2 RGB image before RCM tag embedding; it is an image intermediate, **not a chaotic sequence**. `final_marked_rgb` is the final RCM-marked RGB output. Both are row-major RGB uint8 bytes, serialized MSB-first and truncated at the stated length.

Complete per-test component outcomes (pass / fail / not-applicable):

| Test | Step-2 intermediate | Final marked RGB |
|---|---:|---:|
| Frequency | 0 / 10 / 0 | 0 / 10 / 0 |
| BlockFrequency | 0 / 10 / 0 | 0 / 10 / 0 |
| CumulativeSums | 0 / 20 / 0 | 0 / 20 / 0 |
| Runs | 0 / 10 / 0 | 0 / 10 / 0 |
| LongestRun | 0 / 10 / 0 | 0 / 10 / 0 |
| Rank | 0 / 10 / 0 | 0 / 10 / 0 |
| FFT | 0 / 10 / 0 | 0 / 10 / 0 |
| NonOverlappingTemplate | 144 / 1336 / 0 | 145 / 1335 / 0 |
| OverlappingTemplate | 0 / 10 / 0 | 0 / 10 / 0 |
| Universal | 0 / 10 / 0 | 0 / 10 / 0 |
| ApproximateEntropy | 0 / 10 / 0 | 0 / 10 / 0 |
| RandomExcursions | 0 / 0 / 80 | 0 / 0 / 80 |
| RandomExcursionsVariant | 0 / 0 / 180 | 0 / 0 / 180 |
| Serial | 0 / 20 / 0 | 0 / 20 / 0 |
| LinearComplexity | 10 / 0 / 0 | 10 / 0 / 0 |

**step2_intermediate component totals:** pass=154, fail=1466, not-applicable=260.

**final_marked_rgb component totals:** pass=155, fail=1465, not-applicable=260.

No single overall NIST pass is computed. SP 800-22, NPCR, and UACI are statistical diagnostics, not proofs of security. Per-stream source hashes, exact command, test setup, and script hashes are in `authenticated_tpe/output/nist_sp800_22/provenance.txt`.


## Reproduction
From the repository root:

```bash
.venv/bin/python -m pytest authenticated_tpe/tests -q
.venv/bin/python authenticated_tpe/experiments/run_authenticated_tpe.py
.venv/bin/python authenticated_tpe/experiments/check_authenticated_tpe_tampering.py
```

## Artifact map

- Method notes: [`docs/AUTHENTICATED_TPE.md`](../docs/AUTHENTICATED_TPE.md)
- Raw clean-image results: [`output/clean_authentication_results.csv`](../output/clean_authentication_results.csv)
- Tampering results: [`output/tamper_results.csv`](../output/tamper_results.csv)
- Capacity results: [`output/capacity_results.csv`](../output/capacity_results.csv)
- Key derivation vectors: [`output/key_derivation_vectors.txt`](../output/key_derivation_vectors.txt)
- Run provenance: [`output/provenance.txt`](../output/provenance.txt)
- Original chaotic reproduction report: [`../../tpe_rdh_reproduction/reports/ORIGINAL_TPE_RDH_REPORT.md`](../../tpe_rdh_reproduction/reports/ORIGINAL_TPE_RDH_REPORT.md)
- Cross-project comparison: [`../../reports/COMPARISON.md`](../../reports/COMPARISON.md)
