# Paper-Specific Reversible Block-Group Authentication Prototype

This is a separate research implementation of the professor-provided 16-page
specification, *Reversible Block-Group Authentication for Thumbnail-Preserving
Encrypted Color Images Using Reversible Contrast Mapping and HMAC-SHA256*.
It is not a replacement for, or modification of, the existing chaotic
TPE/RDH reproduction in `src/chaos.py`, `src/permutation.py`, `src/rdh.py`,
`src/substitution.py`, and `src/pipeline.py`. The new implementation is
`src/authenticated_tpe.py`, its tests are in `tests/test_authenticated_tpe.py`,
and its experiment is `experiments/run_authenticated_tpe.py`.

The source method is specified for 512 x 512 RGB `uint8` images, 32 x 32
blocks, 256 blocks per channel, 512 adjacent horizontal pairs per block, four
blocks per group, and a 256-bit HMAC-SHA256 tag. This prototype enforces that
image shape and dtype.

## Processing flow

1. **Step 1, pair-sum-preserving transform:** for each channel, raster-order
   block and horizontal pair, enumerate all first-pixel values for the pair's
   sum. Partition the values by whether the corresponding pair is in `D_c`,
   keep the source pair's class, and cyclically shift within that class by a
   key-derived offset. The pair sum and `D_c` membership are unchanged.
2. **Step 2, smaller-pixel re-encryption:** shift the strictly smaller pixel
   cyclically modulo the larger pixel using one derived `r1` value per block;
   equal pixels remain unchanged. This is inverted before Step 1.
3. **Authentication and marking:** derive independent per-channel groupings,
   authenticate the Step-1 blocks in each ordered four-block group, and embed
   each complete 256-bit code reversibly into the group's Step-2 pairs using
   RCM. If any one group cannot hold its tag, discard every provisional group
   mark and instead embed one tag over the fixed-order whole image.
4. **Verification and recovery:** try every group, then whole-image mode as
   specified, restore RCM carrier pairs, invert Step 2, and verify HMAC before
   releasing a recovered image. A failed verification returns no plaintext.

## Encodings and derivations

All labels are literal ASCII bytes. Concatenation is byte concatenation. A
channel index is exactly one byte (`0`, `1`, or `2` for R/G/B); block and pair
indices are unsigned two-byte big-endian integers. An ImageID is exactly 16
bytes. HMAC output is the 32-byte SHA-256 digest.

```text
Kch,c    = HMAC-SHA256(UserKey, b"channel" || channel_u8)
Ktpe,c   = HMAC-SHA256(Kch,c, b"tpe")
Kr1,c    = HMAC-SHA256(Kch,c, b"r1")
Kstruct,c= HMAC-SHA256(Kch,c, b"struct")
Kauth    = HMAC-SHA256(UserKey, b"auth")
Kgroup   = HMAC-SHA256(Kauth, ImageID || channel_u8 || Bid0_u16be || ... || Bid3_u16be)
Kimage   = HMAC-SHA256(Kauth, b"image" || ImageID)
t        = BE32(HMAC-SHA256(Ktpe,c, b"tpe-shift" || ImageID || Bid_u16be || k_u16be)[0:4]) mod class_size
r1       = BE32(HMAC-SHA256(Kr1,c, b"r1" || Bid_u16be)[0:4]) mod 4
```

The `r1` reduction uses the first four digest bytes, big-endian. The paper says
to interpret the digest deterministically and reduce modulo four but does not
specify byte count or endianness; this is a declared implementation choice.
Per-pair `t` uses the first four digest bytes as specified. The ordered block
IDs enter both `Kgroup` and the group MAC message. Each Step-1 block contributes
exactly 1,024 bytes in row-major order. The whole-image MAC message is all 768
Step-1 blocks in R, then G, then B channel order and raster block order,
followed by ImageID.

## ImageID handling

`generate_image_id()` uses Python's OS-backed `secrets.token_bytes(16)`.
Production callers must generate a new value for every protected image and
retain it privately in their own owner records. The marked image and the
experiment artifacts do not store ImageID. The API permits a caller-supplied
ImageID for deterministic tests; the prototype does not keep a persistent
registry and therefore cannot enforce uniqueness across calls or processes.
Fresh-ID generation and the ID-bound pair shift are tested. Reuse prevention
is an owner-side operational requirement.

The experiment key and ImageIDs are deterministic public test fixtures solely
to make its results reproducible. They are not secrets and must never be used
for production protection.

## Grouping and RCM

Grouping follows the provided HMAC_DRBG(HMAC-SHA256) description: entropy input
is `Kstruct,c`, nonce is empty, personalization is `b"group-perm"`, K and V
are initialized to the required 00 and 01 strings, and the Fisher-Yates shuffle
uses rejection sampling on big-endian 32-bit outputs. The paper only provides
the first eight permutation values for `Kstruct = 00..1f`; the test verifies
that prefix and an independent compact reference implementation pins the full
permutation. The SHA-256 digest of its 256-byte block-ID sequence is
`55f272be5c1686f05a22714dba3a2651d79cb11d14df3d66ba715d3e38ba8c38`.

The implementation defines `D` by checking both transformed coordinates are
within `[0,255]`. It defines `D_c` by excluding pairs where both original
coordinates are odd and either transformed coordinate is 1 or 255. T pairs
carry a bit in the transformed second LSB and use the first transformed LSB as
the T marker; O pairs carry a bit in the second original-pair LSB; N pairs
store the first original LSB for later restoration. Embedding visits group
pairs in `k = 511..0`, then group block order `0..3`. It stops at net capacity
`A-N = 256`, placing the tag first and saved N-pair LSBs after the tag. Whole
image order is `k = 511..0`, then channel R/G/B, then block ID 0..255.

The PDF describes which LSBs are overwritten and gives inverse equations but
does not spell out every arithmetic detail of implementing the ceiling with
signed integer division. We use exact mathematical ceiling division and clear
both overwritten LSBs before applying the inverse to T pairs. Exhaustive
testing over all 65,536 pairs confirms T/O/N classification and reversible
one-bit embedding/restoration under this interpretation.

## API and verification behavior

- `protect_image(image, user_key, image_id=None)` validates the image, makes a
  fresh ImageID if omitted, and returns a `ProtectResult` with the marked array,
  mode, and ImageID held only in memory.
- `verify_and_decrypt(marked_image, user_key, image_id)` returns a
  `VerifyResult`. `recovered_image` is populated only after successful
  authentication; all negative cases return `None`.
- `group_blocks`, `derive_keys`, `embed_group_tag`, `extract_group_tag`,
  `rcm_forward`, and `rcm_inverse` expose component-level operations.

Group mode verifies all 192 channel/group codes. A failure identifies the
affected group of four scattered blocks, not the exact modified block or pixel.
The implementation reports failed groups only if at least one group code
verifies, because failed group parses alone cannot establish that the file was
created in group mode. No partially authenticated plaintext is returned.
Whole-image mode provides only image-level yes/no authentication and no
localization. There is no mode flag or other ciphertext side information;
verification tries group mode first and whole-image mode second.

## Validation scope and limitations

This is a prototype of the supplied method, not evidence of a secure modern
encryption construction. Authentication is conditional on a secret,
unpredictable UserKey, correct confidential owner-side ImageID handling,
lossless storage, and correct implementation. HMAC known-answer tests, exact
recovery tests, and tamper tests do not prove overall cryptographic security.
No independent cryptanalysis, formal proof, or production hardening is
provided. Step 1 deliberately preserves every adjacent pair sum and therefore
leaks those sums; the source method itself notes that this makes the output
recognizable at fine granularity. Step 2 uses only four `r1` values per block
and is not relied on for confidentiality. Lossy JPEG, resizing, and color
conversion are not supported and should invalidate verification.

The professor's PDF's attack and quality tables are reported as the PDF's
claims, not as results reproduced by this code. This project's experiments
use UCT images and deterministic fixtures; they do not reproduce the PDF's
Colab notebook, its exact image-selection/resizing operations, or its entire
attack suite. The full method specification does not provide a full DRBG
expected stream or all original notebook details; the paper's permutation
prefix and our independently calculated full-permutation digest document the
local deterministic convention. The NIST DRBG vectors page is cited in the
report, but its archive is not imported into this prototype.

The previous chaotic TPE/RDH implementation and its tests remain unchanged.
This separate implementation must not be used to imply that the previous
method was authenticated, or that NIST SP 800-22, NPCR/UACI, entropy,
correlation, or exact recovery proves security.
