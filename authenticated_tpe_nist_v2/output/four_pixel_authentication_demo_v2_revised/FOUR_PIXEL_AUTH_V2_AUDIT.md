# Four pixel authentication v2 audit

## Result and scope

This implementation is an adaptation that combines the paper's four-pixel sum-preserving substitution (SPE) with the repository's 32×32 TPE schedule, reversible data hiding (RDH), block-group authentication, and an AEAD-protected sidecar. The article's four-pixel equations are reversible under the tested boundaries, but the full paper method is not reproduced: its generator/key schedule and image-ID convention differ from this repository. No cryptographic-security claim follows from the round-trip or tamper tests.

## Paper and equation audit

Source: Kao, C.-H., Chen, G.-Z., Hou, Y.-Y., and Liao, T.-L., “Four-pixel sum-preserving encryption using the chaotic map for high thumbnail-preserving image security,” *Scientific Reports* 16, 21218 (2026), DOI [10.1038/s41598-026-47090-9](https://doi.org/10.1038/s41598-026-47090-9). We inspected the published article and its Supplementary Note. The named `audit/tpe-repo` materials are not present in this checkout.

The paper processes pixel values sequentially in groups `(a,b,c,d)`. The adapter flattens each 32×32 channel block in row-major order and groups consecutive values by four. This ordering matches the article's sequential grouping. Each block contains 1,024 values, so there are no tail pixels in these 512×512 experiments.

The Supplementary Note sets `e=255`, gives the four case inequalities, and specifies the key domain `r ∈ [0,255]`. The article's main text says the scheduled key is `r=floor(255u)+1`, for `u∈(0,1)`, so actual schedule values are `1…255`. The adapter maps its repository 2D-CSM value `x∈[-1,1]` to `u=(x+1)/2` and applies that stated integer rule, with clipping at the endpoint. This preserves the paper's `r` mapping, but not its generator.

The article's prose summarizes the sum cases as `[0,255]`, `[256,510]`, `[511,765]`, and `[766,1020]`. The Supplementary Note instead says Case 1 is `S<e`, Case 2 is `e≤S≤2e`, and so on, with `e=255`; that assigns `S=255` to Case 2. The implementation follows the explicit appendix inequalities. Both assignments are reversible at this boundary, but they are not identical encryption mappings.

For the apparent Case 2 inverse sign error, the forward high-sum branch is

`c′ = e − ((e − c + r) mod M)`, where `M = 2e − (S−S1) + 1`.

Rearranging gives `e−c′ ≡ e−c+r (mod M)`, hence `c = e − ((e−c′−r) mod M)`. The Supplementary Note prints `+r` inside the inverse expression. The code uses `−r`; a directed test at `S=256` confirms that the printed sign does not recover the test tuple. Tests also cover all case boundaries and 20,000 deterministic random tuples with `r=0…255`. This is implementation-level verification, not an exhaustive evaluation of all 256⁴ tuples.

## Material departures from the paper

1. The paper describes its own keyed generator and permutation choices. This prototype uses the repository's 2D-CSM schedule and channel-key derivation; only the integer mapping to `r` follows the article's stated rule.
2. The repository pipeline resolves its TPE schedule identifier from the input image when none is supplied. That identifier is stored encrypted in the sidecar. The paper instead specifies a public, externally supplied image identifier independent of plaintext-derived schedule state.
3. The paper does not define the proposed authentication and payload wrapper. This adapter adds one 256-bit HMAC-SHA256 tag per RGB channel to the repository's native histogram-shifting RDH stream; the demonstration payload is carried in the red-channel stream. The outer layer adds HMAC authentication tags over four-block groups and reversible RCM marking for localization.
4. The wrapper adds a stable sorted-value logical pairing layout and a reversible per-pixel block-sum correction map. The correction restores each displayed 32×32 block sum after RDH/authentication marking. These sidecar structures are not in the paper.
5. The prototype requires RGB images with dimensions divisible by 32. It does not implement the paper's other block sizes or its partial-block tail rules.
6. Two independent 32-byte keys are used: a TPE key and an authentication key. This separation is part of this integration; no key is committed.

## Bundle format and key requirements

A bundle is a lossless RGB PNG plus a binary sidecar. The v1 sidecar starts with a 44-byte public header containing the magic, format version, flags/reserved fields, height, width, a random 16-byte ImageID, and a 12-byte ChaCha20-Poly1305 nonce. The entire header is authenticated as AEAD associated data. The header values are public; changing any authenticated field invalidates the sidecar.

The encrypted sidecar body contains the logical pairing map, reversible sum-correction vector, and TPE schedule identifier. The authentication key derives the group-authentication and sidecar-AEAD keys. The TPE key regenerates the adapted permutation/substitution schedule. Neither key is stored in the bundle, output metrics, or Git. A fresh process needs only the PNG, sidecar, TPE key, and authentication key; no source image, external ImageID, or in-memory encryption object is required.

The user payload is **not** stored in the sidecar for this adapter. It is carried by the native RDH stage in the red-channel image data and recovered by the RDH extractor after authentication succeeds. An expected payload can be supplied by an application for comparison, but it is not an input to recovery.

## Threat model and limits

Tests model an attacker who can alter, truncate, or mismatch the PNG and sidecar, replace blocks with another encrypted image, or provide wrong keys/IDs, but does not know the keys. Group HMACs identify affected four-block groups after the sidecar opens. If the sidecar/header/key fails AEAD validation, no group map can be trusted and the report therefore lists no localized group; recovery is withheld. A failed native RDH tag or TPE key also withholds the image.

A complete valid PNG+sidecar bundle can be replayed or substituted as a unit unless the application compares the public ImageID or another object identity against an expected value. These checks do not prove resistance to chosen-plaintext cryptanalysis, key compromise, implementation side channels, or all possible tampering patterns. The chaos-based TPE layer is not a replacement for a conventional confidentiality cipher.

## Measurements

Full-image PSNR compares the source RGB image with the final authenticated ciphertext, after all RDH, RCM, and correction stages. It uses `10 log10(255²/MSE)`, where MSE is the arithmetic mean over all pixel-channel samples. The reported aggregate is the arithmetic mean of the six per-image PSNR values; the per-image range is reported separately.

Thumbnail fidelity is computed from the per-channel arithmetic mean of every non-overlapping 32×32 block. Its MSE is the arithmetic mean over the resulting 16×16×3 thumbnail values. A zero MSE is reported as exact equality and PSNR `+∞` (encoded as JSON `null`), not as a finite score. Thumbnail fidelity and full-image PSNR are distinct measurements.

## Tests and NIST status

The v2 regression suite tests transform inverses and sums, key quantization, saved-file recovery in a fresh interpreter, payload extraction from the serialized PNG, all three color channels, multiple block/group locations, same-group and multi-group edits, cross-image block and sidecar replacements, wrong keys and IDs, and altered/truncated sidecars. Authentication failures return no recovered image.

The historical full repository suite had missing external fixtures; it is not claimed to pass. The previous method's NIST SP 800-22 results are not attributed to this variant. No new NIST campaign was run: the predeclared categories bind to the prior variant's key/stream definitions and tag message, while this adaptation adds a 2D-CSM-derived `r` schedule and a different authenticated carrier. Changing the predefined key pool or stream definitions to fit this method would no longer be the predeclared protocol. Therefore this v2 report contains no NIST pass/fail result for the new variant.
