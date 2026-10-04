# Executive summary — original chaotic TPE/RDH

## Implemented and tested

This project implements the original chaotic TPE/RDH pipeline: chaotic-map generation, `Upsilon_P`/`Upsilon_S`, block permutation, histogram-shifting RDH, sum-preserving substitution, decryption and exact image/payload recovery.

- Test suite: **83 passed, 14 warnings in 2.37s**.
- UCT all-block experiment: 24/24 rows report exact recovery.
- NIST SP 800-22 component outcomes across recorded streams: 894 pass, 2502 fail, 364 not applicable. Results are mixed with substantial failures.
- NPCR/UACI, entropy, correlation and block-sum results are dynamically summarized in [the detailed report](ORIGINAL_TPE_RDH_REPORT.md) from checked-in artifacts.

## Limitations and final status

The implementation has documented assumptions where the paper is underspecified. Statistical tests do not establish cryptographic security. The original pipeline has no authentication layer.

> The original chaotic TPE/RDH pipeline passes its functional, key-reuse, recovery, and documented image-level validation tests. NIST SP 800-22 results are mixed and include substantial failures. These tests do not establish cryptographic security.

Final status: functional reproduction prototype with documented limitations; cryptographic security is not established.

## Provenance

Branch `authenticated-tpe-paper`, source commit `ec2661b690fa544b32b4d785fca3da46dc5a9603`; current worktree state: `dirty`. See the detailed report for runtime versions, image hashes, commands, artifact paths and generation script.
