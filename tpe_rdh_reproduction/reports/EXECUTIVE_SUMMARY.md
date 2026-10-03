# Executive Summary — Original Chaotic TPE/RDH

## What was implemented

The project implements the original paper’s chaotic TPE/RDH pipeline: 2D-CSM chaotic-map generation of `Upsilon_P` and `Upsilon_S`, block permutation, histogram-shifting RDH, sum-preserving pair substitution, and inverse decryption/recovery. Several underspecified paper details use documented implementation conventions.

## What was tested and found

- The original project test suite passed **83 tests** after the authenticated prototype was separated.
- UCT image validation passed **24/24** image/block-size runs for exact image recovery, payload recovery, zero maximum recovery error, and post-RDH block-sum preservation.
- Section 6-style validation passed exact recovery in **16/16** runs across four `skimage.data` images and block sizes 8, 16, 32, and 64.
- Same-key/different-image fixtures produced different identifiers, chaotic matrices, and ciphertexts.
- The NIST SP 800-22 Rev. 1a run has **484 pass / 1,292 fail / 104 not applicable** chaotic-matrix component outcomes and **410 / 1,210 / 260** final-ciphertext outcomes. Failures are substantial and retained as observed.
- NPCR/UACI, entropy, correlation, and thumbnail/block-sum results are documented with their specific fixtures and definitions in [`ORIGINAL_TPE_RDH_REPORT.md`](ORIGINAL_TPE_RDH_REPORT.md).

## Limitations and final status

Project images and some parameters differ from the paper; key-to-chaos conversion, RDH metadata, and several experiment details are implementation choices. The implementation has no authentication layer. NIST results, NPCR/UACI, entropy, and correlation do not establish cryptographic security.

> The original chaotic TPE/RDH pipeline passes its functional, key-reuse, recovery, and documented image-level validation tests. NIST SP 800-22 results are mixed and include substantial failures. These tests do not establish cryptographic security.

## Provenance

Branch `authenticated-tpe-paper`, report source commit `7bbe3cf32197b3bba5f5f868df90b9c417c4da66`; worktree was clean at report-generation start. Test environment: Python 3.11.0, NumPy 2.4.4, Pillow 12.0.0, scikit-image 0.25.2, pytest 8.4.2. The detailed report lists UCT input TIFF SHA-256 values and the separate historical source commits for NIST, Section 6, and synthetic runs.
