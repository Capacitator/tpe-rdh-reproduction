# Test Plan And Coverage

This file records the tests used to check the Section 5 implementation. The main goal is to verify deterministic behavior, exact recovery, and correct data extraction for the project implementation.

## 5.1 Chaotic Matrices

- Determinism: same parameters produce identical `Upsilon_P` and `Upsilon_S`.
- Shape: output matrices are exactly `M x N`.
- Length/discard accounting: retained sequences contain exactly `M*N` values after the specified discard count.
- Parameter sensitivity smoke test: changing one explicit numeric parameter changes at least one output value.
- No hidden randomness: function output depends only on explicit inputs.

Covered for the explicit demo parameters used in this project. The paper's full key conversion, `T -> T_tau`, `kappa_2` conversion, and exact construction of `Upsilon_P`/`Upsilon_S` are not fully specified in the accessible text.

## 5.2 Permutation Encryption

- Identity-size sanity: a single `b x b` block can be permuted and inversely permuted exactly.
- Multi-block reversibility: inverse permutation recovers the exact original channel for at least a `2b x 2b` synthetic channel.
- Block-sum preservation: every `b x b` block has the same sum before and after permutation.
- Value multiset preservation: every block has the same sorted pixel values before and after permutation.
- RGB handling: each channel is permuted independently and channel shapes are preserved.
- Invalid dimensions: image dimensions not divisible by `b` raise a clear error unless a paper-supported edge policy is later found.

Implemented with row-major flattening, stable ascending sort, and a documented mapping direction.

## 5.3 RDH Embedding

- Peak/zero selection: histogram peak and zero point are selected as specified for controlled histograms.
- Basic `P < Z` embedding: known bitstream embeds into peak pixels and extracts exactly.
- Basic `P > Z` embedding: symmetric case extracts exactly if implemented after confirming recovery rule.
- Image recovery: extraction restores the exact input channel before RDH.
- First-row LSB storage: original 16 LSBs are restored exactly.
- Capacity failure: embedding too many bits raises a clear error.
- Minimum-point overhead: if no zero bin exists, affected pixels are restored exactly after extraction.
- RGB/channel policy: once decided, test payload split/recovery across channels.

Covered with an explicit metadata header, first-16-pixel exclusion, channel-0 payload policy, and symmetric `P > Z` handling. These choices make the project executable while keeping the missing paper format details documented.

## 5.4 Substitution Encryption

- Eq. (9) count: verify same-sum pair counts for sums `0`, `1`, `255`, `256`, `509`, and `510`.
- Eq. (7)/Eq. (10) round trip: every valid pair for selected sums maps to an index and back exactly.
- Modular encryption inverse: `(eta + delta) mod count` followed by `(eta_e - delta) mod count` recovers `eta`.
- Pair-sum preservation: each encrypted pair has the same sum as the input pair.
- Block-sum preservation: every `b x b` block sum is unchanged after substitution.
- Full substitution reversibility: inverse substitution restores the exact marked channel.
- Boundary pixel values: include pairs containing `0`, `255`, and sums on both sides of `d`.

Implemented with row-major pairing and caller-supplied `vartheta`. The numeric `vartheta` value remains an implementation assumption.

## 5.5 Full Decryption/Recovery

- Component composition: permutation -> inverse permutation recovers exactly.
- RDH composition: embed -> extract/recover returns exact carrier and payload.
- Substitution composition: substitute -> inverse substitute recovers exact marked image.
- Full grayscale pipeline: after all component choices are explicit, original channel and payload recover exactly.
- Full RGB pipeline: original RGB image and payload recover exactly.
- Thumbnail preservation: encrypted marked image preserves each thumbnail block sum after substitution, subject to RDH placement policy.
- Metrics sanity: exact recovery gives infinite PSNR and SSIM of 1.
- Wrong-parameter negative test: decryption with an altered chaotic parameter is expected to fail exact original-image recovery.

Covered for the documented project choices, including a wrong-parameter negative test. A complete paper-level test suite would also need the authors' exact key schedule and exact Mode 1/Mode 2 definitions.

## Experiment Readiness Tests

- File IO: PNG load/save preserves array dimensions and dtype.
- Reproducibility: fixed inputs and parameters produce byte-identical output arrays.
- Timing harness: measures algorithm time without image-display overhead.
- Small-image smoke suite: all reversible tests pass on synthetic arrays before running larger image experiments.
