# Section 5 Implementation Notes

Sources:

- Paper: "A dual-mode thumbnail-preserving encryption scheme based on chaotic system and reversible data hiding", Sec. 5.1-5.5.
- Local map: `docs/paper_map.md`.

These notes summarize how Section 5 of the paper was interpreted for this project. They also list places where the accessible paper text does not give enough detail for an exact paper-level implementation.

## Current Implementation Status

- 5.1 Chaotic matrices: implemented in `src/chaos.py` with a documented 256-bit key conversion, image identifier `T`, derived `T_tau`, derived `kappa_1`, derived `kappa_2`, and the two-stage iteration procedure described by Section 5.1. This preserves the paper's required key-reuse behavior: different images under the same key derive different chaotic matrices. In the pipeline, `T` is derived from plaintext image bytes by default during encryption and returned for storage with the ciphertext.
- 5.2 Permutation encryption: implemented in `src/permutation.py` with row-major flattening, stable ascending sort, and exact inverse permutation.
- 5.3 RDH embedding: implemented in `src/rdh.py` with an explicit metadata header because the paper does not define a parseable payload/overhead format.
- 5.4 Substitution encryption: implemented in `src/substitution.py` for row-major two-pixel pairs using caller-supplied `vartheta`.
- 5.5 Decryption/recovery: implemented in `src/pipeline.py`; integration tests verify exact RGB recovery and payload recovery.

This implementation is a working reproduction prototype for the executable stages. The paper-required key-reuse property is implemented; the exact author byte-level key/T conversions and some format details remain outside the available information.

## Subsection Notes

### 5.1 Chaotic Matrices

- Inputs: image dimensions `M`, `N`; initial state `x_0`, `y_0`; control parameters `r_1`, `r_2`; transient count `kappa_1`; image identifier `T`; converted integer `T_tau`; dynamic discard `kappa_2`.
- Outputs: `Upsilon_P` and `Upsilon_S`, each shaped `M x N`.
- Equations involved: Eq. (4); Eq. (2) and Eq. (3) are background maps used to define Eq. (4).
- Dependencies on previous steps: none inside Section 5, but relies on Sec. 4 definition of 2D-CSM.
- Expected reversible property: not reversible by itself; must be exactly reproducible from the same parameters during decryption.
- Paper section reference: Sec. 5.1.

### 5.2 Permutation Encryption

- Inputs: original image/channel matrices, `Upsilon_P`, block size `b`.
- Outputs: permutation-encrypted image/channel matrices.
- Equations involved: no numbered equation; described by block partitioning, sorting, and positional remapping.
- Dependencies on previous steps: requires `Upsilon_P` from Sec. 5.1.
- Expected reversible property: inverse permutation with the same block mappings must exactly recover the input to Sec. 5.2; each `b x b` block sum is preserved.
- Paper section reference: Sec. 5.2.

### 5.3 RDH Embedding

- Inputs: permutation-encrypted image/channel, payload bitstream, histogram peak `P`, zero/minimum point `Z`, first-row LSBs, possible minimum-point coordinate overhead.
- Outputs: marked image/channel, embedded payload, recoverable overhead.
- Equations involved: Eq. (1) for `P < Z`; Sec. 3.2.1/3.2.2 prose for histogram shifting and extraction.
- Dependencies on previous steps: requires permutation-encrypted image from Sec. 5.2.
- Expected reversible property: extraction must recover embedded bits and restore the exact permutation-encrypted image/channel.
- Paper section reference: Sec. 5.3, with RDH background from Sec. 3.2.

### 5.4 Substitution Encryption

- Inputs: marked image/channel, `Upsilon_S`, block size `b`, amplification coefficient `vartheta`, pixel maximum `d = 255`.
- Outputs: final encrypted marked image/channel.
- Equations involved: Eq. (6), Eq. (7), Eq. (8), Eq. (9), Eq. (10).
- Dependencies on previous steps: requires marked image from Sec. 5.3 and `Upsilon_S` from Sec. 5.1.
- Expected reversible property: decryption must exactly recover the marked image/channel; each two-pixel pair sum and each thumbnail block sum must be preserved.
- Paper section reference: Sec. 5.4 and Algorithm 1 caption.

### 5.5 Decryption and Recovery

- Inputs: encrypted marked image, parameters needed to regenerate `Upsilon_P` and `Upsilon_S`, block size `b`, `vartheta`, `d`, and any required RDH parsing metadata.
- Outputs: recovered original image and extracted embedded information.
- Equations involved: inverse of Eq. (8) by algebraic reversal, Eq. (7), Eq. (10), RDH extraction/recovery rules from Sec. 3.2.2 and Sec. 5.5.
- Dependencies on previous steps: reverses Sec. 5.4, then Sec. 5.3, then Sec. 5.2.
- Expected reversible property: recovered image must equal original exactly; extracted payload must equal embedded payload exactly.
- Paper section reference: Sec. 5.5.

## Required Parameters Not Numerically Specified

- The authors' exact key-to-chaos convention, if different from the project convention.
- The authors' exact `T -> T_tau -> kappa_2` convention, if different from the project convention.
- `vartheta` / `theta`: amplification coefficient for Eq. (6).
- Permutation sorting direction and tie-breaking rule.
- Pairing order for pixels and chaotic values inside each `b x b` block.
- RDH overhead encoding format for original first-row LSBs and minimum-point coordinates.
- Payload length or terminator format.
- RGB channel policy for `P`, `Z`, overhead, payload segmentation, and first-row LSB storage.
- Handling rule for image dimensions not divisible by `b`.

## Paper Details Not Fully Specified

### Key Conversion

Paper detail not fully specified

- Why it matters: chaotic encryption must regenerate identical matrices during decryption and must support the claimed key space.
- What the paper explicitly says: the system has a 256-bit key space; Sec. 5.1 uses `x_0 = 0.3`, `y_0 = 0.2`, and `r_1 = r_2 = 50`.
- Project note: the code uses a documented 256-bit key convention. The key is split into four 64-bit fields for `x0`, `y0`, `r1`, and `r2`, and `kappa_1` is derived from `SHA-256(key || b"kappa_1")`.

### `kappa_1`

Paper detail not fully specified

- Why it matters: changing `kappa_1` changes every chaotic value and therefore all permutations/substitutions.
- What the paper explicitly says: initial `kappa_1` sequence values are discarded because of transient effects.
- Project note: the code derives `kappa_1` from the 256-bit key in the range `128..1151`.

### `T`, `T_tau`, and `kappa_2`

Paper detail not fully specified

- Why it matters: these values are the paper's mechanism for preserving key-reuse security across images while keeping decryption reproducible.
- What the paper explicitly says: unique image identifier `T` is converted to positive integer `T_tau`; after `kappa_1 + T_tau` iterations, output is converted to integer `kappa_2`.
- Project note: the code hashes image identifier `T` into `T_tau` in the range `1..1024`, derives `kappa_2` from the first-stage chaotic output in the range `1..1024`, and then uses the Section 5.1 two-stage iteration procedure. The pipeline derives `T` from plaintext image bytes when no explicit identifier is supplied and requires the stored identifier during decryption.

### Independent Chaotic Matrices

Paper detail not fully specified

- Why it matters: `Upsilon_P` and `Upsilon_S` drive different encryption stages, so their construction affects all results.
- What the paper explicitly says: two independent chaotic matrices are generated; two valid 1D sequences are reshaped into `M x N` matrices.
- Project note: the code uses the generated `x` and `y` outputs as the two matrices.

### Permutation Mapping

Paper detail not fully specified

- Why it matters: inverse permutation must use the same source-to-destination convention.
- What the paper explicitly says: each chaotic block is reordered by value to form `Upsilon_P'`, which acts as a positional mapping template.
- Project note: the code uses row-major flattening and stable ascending sorting.

### Pairing Order

Paper detail not fully specified

- Why it matters: substitution decryption must pair pixels and chaotic values in exactly the same order.
- What the paper explicitly says: pixels and chaotic matrix elements inside each thumbnail block are grouped in pairs.
- Project note: the code uses row-major two-pixel pairing.

### Amplification Coefficient `vartheta`

Paper detail not fully specified

- Why it matters: `delta` controls substitution offsets and therefore ciphertext and inverse decryption.
- What the paper explicitly says: `vartheta` is predefined and `vartheta >> 1`.
- Project note: the code uses a caller-supplied `vartheta` value.

### RDH Channel and Metadata Format

Paper detail not fully specified

- Why it matters: extraction cannot separate payload, first-row LSB overhead, and coordinate overhead without a format.
- What the paper explicitly says: color images have per-channel histograms; first 16 top-row LSBs store binary `P` and `Z`; original LSBs and minimum-point coordinates are overhead.
- Project note: the code uses an explicit metadata header and splits payload bits across RGB channels in channel order.

### Histogram Recovery Range

Paper detail not fully specified

- Why it matters: incorrect inverse shifting breaks lossless recovery.
- What the paper explicitly says: Sec. 3.2.2 describes extraction for both `P < Z` and `P > Z`; Sec. 5.5 says values `x in (P, Z]` are decremented.
- Project note: the code uses a symmetric inverse for the `P > Z` case.

### Algorithm 1 and Figures

Paper detail not fully specified

- Why it matters: Algorithm 1 may contain loop bounds, pairing order, or assignment details omitted from prose.
- What the paper explicitly says: Algorithm 1 is titled "Substitution Encryption Algorithm"; Fig. 6 shows the whole encryption and embedding process.
- Project note: the implementation follows the equations and prose that are available in text form.

## Pseudocode Only

### 5.1 Chaotic Matrix Generation

```text
INPUT: M, N, x0, y0, r1, r2, kappa1, T
OUTPUT: Upsilon_P, Upsilon_S

convert T to positive integer T_tau
iterate Eq. (4) for kappa1 + T_tau steps
convert chaotic output to integer kappa2

reset or continue chaotic system according to paper decision
iterate Eq. (4) for kappa1 + kappa2 + M*N steps
discard first kappa1 + kappa2 values
keep next M*N values from sequence A
keep next M*N values from sequence B
reshape sequence A to M x N as Upsilon_P
reshape sequence B to M x N as Upsilon_S
return Upsilon_P, Upsilon_S
```

Paper detail not fully specified: "reset or continue" and "sequence A/B" are not resolved by the accessible text.

### 5.2 Block Permutation

```text
INPUT: image channels, Upsilon_P, block size b
OUTPUT: permutation-encrypted channels

for each channel:
    split channel into non-overlapping b x b blocks
    split Upsilon_P into matching b x b blocks
    for each image block and chaotic block:
        flatten chaotic block in chosen order
        sort flattened chaotic values to obtain permutation indices
        flatten image block in the same order
        reorder image pixels according to permutation indices
        reshape reordered pixels back to b x b
    combine permuted blocks into full channel
combine channels into permuted image
return permuted image
```

Paper detail not fully specified: sorting direction, tie handling, flatten order, and index mapping direction are not fully specified.

### 5.3 RDH Embedding

```text
INPUT: permutation-encrypted image/channel, payload bits
OUTPUT: marked image/channel

build histogram
find peak point P
find zero point Z
if no zero point exists:
    choose minimum-count point as Z
    record coordinates of affected pixels as overhead
    modify those pixels to create an empty histogram bin

read original LSBs of first 16 pixels in top row
append those 16 bits to overhead
combine overhead and payload into one embedding bitstream

if P < Z:
    shift values in (P, Z) upward by 1
    scan pixels sequentially
    for each pixel equal to P while bits remain:
        leave pixel P for bit 0
        set pixel P+1 for bit 1
else if P > Z:
    shift values in (Z, P) downward by 1
    scan pixels sequentially
    for each pixel equal to P while bits remain:
        leave pixel P for bit 0
        set pixel P-1 for bit 1

write 8-bit P and 8-bit Z into LSBs of first 16 top-row pixels
return marked image/channel
```

Paper detail not fully specified: bitstream format and first-16-pixel exclusion rules are not fully specified.

### 5.4 Substitution

```text
INPUT: marked image/channel, Upsilon_S, b, vartheta, d=255
OUTPUT: encrypted marked image/channel

Upsilon_S_prime = abs(Upsilon_S)
split marked image/channel into b x b blocks
split Upsilon_S_prime into matching b x b blocks

for each image block and chaotic block:
    group chaotic elements into pairs gamma = (gamma1, gamma2)
    group image pixels into pairs tau = (tau1, tau2)
    for each paired gamma and tau:
        delta = floor((gamma1 + gamma2) * vartheta)          # Eq. (6)
        s_tau = tau1 + tau2
        eta = pair_to_index(tau1, tau2, s_tau, d)           # Eq. (7)
        count = same_sum_pair_count(s_tau, d)               # Eq. (9)
        eta_e = (eta + delta) mod count                     # Eq. (8)
        tau_e = index_to_pair(eta_e, s_tau, d)              # Eq. (10)
        replace tau with tau_e
return encrypted marked image/channel
```

Paper detail not fully specified: exact pairing order is not stated in the accessible text.

### 5.5 Decryption

```text
INPUT: encrypted marked image, key/parameters, b, vartheta, d=255
OUTPUT: recovered original image, extracted payload

regenerate Upsilon_P and Upsilon_S using Sec. 5.1

# Reverse substitution
for each encrypted block and matching Upsilon_S block:
    group encrypted pixels and chaotic values using same pairing order as encryption
    for each pair:
        recompute delta from Eq. (6)
        s_tau = encrypted_tau1 + encrypted_tau2
        eta_e = pair_to_index(encrypted_tau1, encrypted_tau2, s_tau, d)
        count = same_sum_pair_count(s_tau, d)
        eta = (eta_e - delta) mod count
        tau = index_to_pair(eta, s_tau, d)
        replace encrypted pair with tau

# Extract RDH payload and recover permutation-encrypted image
read first 16 top-row LSBs as P and Z
scan image row by row, skipping first-row LSB storage
extract bits from P/P+1 or P/P-1 values
parse overhead and payload from extracted bits
restore original first-16 LSBs from overhead
reverse histogram shift
restore minimum-point coordinates from overhead if present

# Reverse permutation
derive Upsilon_P' mappings from Upsilon_P
apply inverse block permutation
return recovered original image and extracted payload
```

Paper detail not fully specified: payload parsing, coordinate overhead parsing, and the `P > Z` histogram inverse require implementation choices.

## Algorithm 1 / Figure Inspection Status

- Verified from accessible paper text: Sec. 5.4 provides the substitution-encryption steps and Eqs. (6)-(10), followed by an image-only Algorithm 1 captioned "Substitution Encryption Algorithm".
- Verified from accessible paper text: Fig. 5 is captioned as chaotic sequence generation, Fig. 6 as the whole encryption/data-embedding process, and Sec. 5.5 describes reverse substitution, RDH extraction/recovery, then inverse permutation.
- Cannot verify from text: Algorithm 1's internal pseudocode, any loop ordering, variable initialization, assignment convention, or pairing order that may appear inside the image.
- Local download attempt status: the Springer media/PDF endpoint returned a challenge page outside the web viewer, so the figure image itself was not available for local inspection/OCR.

Paper detail not fully specified: If Algorithm 1 contains details missing from Sec. 5.4 prose, those details are not available in the accessible text and would need to be checked manually from the PDF.
