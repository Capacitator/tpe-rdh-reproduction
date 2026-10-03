# Authenticated TPE: implementation and evaluation report

## Executive findings

This project is a separate prototype of the professor-supplied reversible block-group authentication method. It combines pair-sum-preserving two-pixel encryption, reversible contrast mapping (RCM), and HMAC-SHA256 tags. It is implemented independently and does not import the original chaotic TPE/RDH pipeline.

On six UCT color-image fixtures, the prototype used group mode, verified all 192 group tags per image, and recovered every image exactly. Seven controlled tampering or credential-mismatch cases were rejected without releasing plaintext. A constructed capacity fixture exercised whole-image fallback successfully. These results establish behavior for the tested cases; they are not a cryptographic security proof or independent cryptanalysis.

## Method and scope

The implementation follows the professor-provided *Reversible Block-Group Authentication for Thumbnail-Preserving Encrypted Color Images Using Reversible Contrast Mapping and HMAC-SHA256* (16 pages; SHA-256 `f0348a3435259037f53028830f4d00056f8ad58f4c87843f3766c924b1a1607d`). This is a documented reconstruction with explicit encoding conventions, not a run of the professor's Colab notebook.

Inputs are 512 × 512 RGB uint8 images, divided into 32 × 32 blocks. Each channel has 256 blocks, 512 adjacent horizontal pixel pairs per block, and 64 groups of four blocks. A full 256-bit HMAC-SHA256 tag is embedded per group, yielding 192 group tags across RGB. If any group cannot carry its tag, group marks are discarded and the implementation falls back to one whole-image tag.

The authentication hierarchy derives channel-specific TPE, block-shift and structure keys from the user key; group tags bind the private ImageID, channel and ordered block IDs, and a separate image tag binds the image ID. Group membership is generated deterministically from a key-derived HMAC_DRBG seed. The exact labels and encodings are specified in [`docs/AUTHENTICATED_TPE.md`](../docs/AUTHENTICATED_TPE.md). In production, the private ImageID is generated with the OS CSPRNG and retained by the owner. The API does not keep a registry to enforce uniqueness.

For each adjacent pair, Step 1 applies a key-derived reversible transform that preserves the pair sum. Step 2 cyclically shifts the smaller pixel value within each block using its derived `r1` value. HMAC_DRBG generates a key-dependent permutation of blocks, partitioned into groups of four. RCM embeds each group's full 256-bit HMAC-SHA256 tag; extraction reverses the mapping to recover and verify those tags. If any group cannot hold its tag, all provisional group marks are discarded and the code attempts one whole-image tag. Decryption/recovery is permitted only after the required tag verification succeeds; failed verification returns no plaintext. Exact encodings and RCM boundary conventions are documented in the method notes.

The six source fixtures are shared, read-only inputs at `../tpe_rdh_reproduction/input/uct_colour/`. The couple and girl source files are 256 × 256 and are resized to 512 × 512 by the experiment script; the other four are already 512 × 512. The experiment uses deterministic public test keys and IDs, which are not production secrets.

## Clean authentication results

| Image | Mode | Tags verified | Exact recovery | Pairs used | Marked vs Step-2 PSNR (dB) | Protect (s) | Verify (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| airplane | group | 192/192 | yes | 54,314 | 30.200616 | 2.829163 | 3.179332 |
| baboon | group | 192/192 | yes | 57,326 | 27.708603 | 2.893875 | 3.142060 |
| couple | group | 192/192 | yes | 80,498 | 32.585125 | 2.998788 | 3.442145 |
| girl | group | 192/192 | yes | 61,936 | 30.054280 | 2.869511 | 3.300352 |
| lena | group | 192/192 | yes | 54,926 | 28.046331 | 2.826731 | 3.117933 |
| peppers | group | 192/192 | yes | 57,430 | 28.999219 | 2.875899 | 3.166885 |

PSNR compares the marked image to the Step-2 encrypted image before RCM marking. It measures marking distortion and is not an authentication or security measure. Timings are measurements from the recorded run and should not be treated as general performance guarantees.

## Tampering and fallback

| Controlled case | Rejected | Failed groups reported | Plaintext released |
|---|---:|---:|---:|
| Single pixel LSB flip | yes | 1 | no |
| Same-channel block swap | yes | 2 | no |
| Cross-channel block swap | yes | 2 | no |
| Wrong user key | yes | 0 | no |
| Wrong ImageID | yes | 0 | no |
| Replacement with another protected image | yes | 0 | no |
| Single pixel LSB flip in whole-image mode | yes | 0 | no |

All seven controlled cases were rejected, with zero observed false acceptances. The first three group-mode edits were localized to one, two and two affected groups respectively. Wrong credentials and image replacement do not identify a group; whole-image fallback also provides no group localization. A separate tampering script independently checked clean verification and recovery, a one-bit tamper, and wrong credentials.

All six natural-image cases had sufficient per-group capacity and used group mode. In a constructed fallback fixture, 3 of 192 groups were below the 256-bit target while whole-image capacity was sufficient; the image used one whole-image tag and recovered exactly. Its one-bit tamper was rejected. Capacity and attack fixtures are detailed in [`output/capacity_results.csv`](../output/capacity_results.csv) and [`output/tamper_results.csv`](../output/tamper_results.csv).

Across the six natural images, measured whole-image net capacity ranged from 269,366 to 356,142 bits; minimum group peak capacity ranged from 333 to 1,619 bits. The fallback fixture had 368,912 whole-image net bits. Clean-image protection time ranged from 2.827 to 2.999 seconds and verification time from 3.118 to 3.442 seconds on the recorded environment. These timings are single-run measurements, not performance guarantees.

## Validation, provenance and limits

The authenticated-only suite command `.venv/bin/python -m pytest authenticated_tpe/tests -q` passed **19 tests**. The independent tampering command `.venv/bin/python authenticated_tpe/experiments/check_authenticated_tpe_tampering.py` also passed. The saved output report records six clean natural-image cases and one constructed fallback case.

### Artifact provenance

- Branch at report start: `authenticated-tpe-paper`.
- Report source commit: `7bbe3cf32197b3bba5f5f868df90b9c417c4da66`; worktree was clean before report files were created.
- Experiment provenance commit: `e004bda185b10c5c0a91061e3715e8c3a0248f6b`; experiment source worktree was clean at run start, before outputs were regenerated.
- Python 3.11.0; NumPy 2.4.4; Pillow 12.0.0; pytest 8.4.2. The source requirements file and historical experiment metadata may identify other versions; use the run provenance for these measurements.
- Shared input paths: `../tpe_rdh_reproduction/input/uct_colour/{airplane,baboon,couple,girl,lena,peppers}.tif`.
- SHA-256 values for each input and source artifact are recorded in [`output/provenance.txt`](../output/provenance.txt).
- The deterministic public UserKey and ImageID fixtures are specified in the same provenance file; they are not production secrets.

Detailed measurements are in [`output/clean_authentication_results.csv`](../output/clean_authentication_results.csv).

The implementation reproduces the method description with documented explicit conventions; it is not an exact reproduction of the professor's unavailable Colab notebook. The paper's reported images and complete attack study were not reproduced here. The two 256 × 256 fixtures are resized for this method, and the fallback case is constructed. No authenticated-method NIST SP 800-22, NPCR/UACI or independent cryptanalysis result is claimed. HMAC-based acceptance and exact recovery in these tests do not prove confidentiality or overall security. ImageID freshness and secrecy, UserKey protection, lossless pixel integrity, and implementation correctness remain operational requirements.

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
