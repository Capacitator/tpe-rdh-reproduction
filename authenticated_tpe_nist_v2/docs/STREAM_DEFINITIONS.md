# Predefined stream definitions

Everything below is a pure function of the constants in `src/streams.py`; the
generated files, their SHA-256 digests and the independence checks are recorded
under `output/`. Parameters for the whole campaign:

* `100` streams per category, `1,000,000` bits (`125,000` bytes) per stream;
* significance level `α = 0.01`;
* official NIST STS 2.1.2 `assess`, ASCII input mode, all tests, default test
  parameters, stream length 1,000,000;
* bit order: MSB first inside each byte; bytes in row-major order; the first
  1,000,000 bits of the 125,000-byte payload are tested.

## Predefined instance pool

| Quantity | Definition |
|---|---|
| `UserKey_i` | `SHA-256("atpe-v2\|userkey\|" ∥ u32be(i))`, 32 bytes |
| `ImageID_i` | `SHA-256("atpe-v2\|imageid\|" ∥ u32be(i))[0:16]`, 16 bytes |

Indices are partitioned so that no key or identifier is ever reused:

| Category | UserKey/ImageID index range |
|---|---|
| `pair_shift` | 1 – 100 |
| `block_r1` | 101 – 700 (6 indices per stream) |
| `auth_tag` | 701 – 2800 (21 indices per stream) |
| `reduced_shift_diag` | 2801 – 2900 |
| `ciphertext_diag` | 2901 – 3000 |
| `recovered_diag` | 3001 – 3100 |
| `hmac_drbg` | no keys; 100 distinct DRBG instantiations, entropy index 1 – 100 |

3,100 disjoint indices, all of them used, verified by
`streams.key_partition_report()`.

## Image pool

| Order | Family | Source |
|---|---|---|
| 0 – 5 | UCT | `tpe_rdh_reproduction/input/uct_colour/{airplane,baboon,couple,girl,lena,peppers}.tif` |
| 6 – 105 | UCID | `github.com/girfa/ColorImageDatasets`, `UCID-1338/1.tif … 100.tif` |

Every image is converted to RGB and resized exactly once to `512 × 512` with
PIL `LANCZOS`, then cached as PNG under `input/images_512/`. The cache file
digest and the raw-pixel digest of all 106 images are recorded in
`output/image_pool_manifest.csv`; all 106 raw-pixel digests are distinct.

* `ciphertext_diag` / `recovered_diag` / `reduced_shift_diag` stream *i* uses
  image order `i − 1` (0 – 99): 100 streams, 100 distinct images, **no image is
  used twice in the whole diagnostic set**.
* `auth_tag` stream *i* uses 21 images with orders
  `((i−1)·21 + t) mod 106`, `t = 0…20`. Inside one stream the 21 images are
  distinct. Across streams an image is reused, which is unavoidable because a
  single image supplies only 192 tags (6,144 bytes) and 125,000 bytes per stream
  are required; the reuse is disclosed, and every `(UserKey, ImageID)` instance
  is unique, so no stream repeats another.

## Categories

### 1. `hmac_drbg` — cryptographic component

Stream *i* = the concatenation of 31,250 consecutive 4-byte HMAC_DRBG
`Generate` calls, each written big-endian, from the DRBG instantiated with

* `entropy_input = SHA-256("atpe-v2|drbg|entropy|" ∥ u32be(i))` (32 bytes),
* `nonce        = SHA-256("atpe-v2|drbg|nonce|" ∥ u32be(i))[0:16]`,
* `personalization = b"group-perm"`.

This is the generator that produces the block-group permutation in the method.
100 distinct instantiations → 100 independent streams.

### 2. `pair_shift` — cryptographic component

Stream *i* enumerates `channel 0…2 × block 0…255 × pair 0…511` for the instance
`(UserKey_i, ImageID_i)` and records the **full 32-byte SHA-256 digest**

```
HMAC-SHA256(Ktpe_c, b"tpe-shift" ∥ ImageID_i ∥ u16be(bid) ∥ u16be(k))
```

in traversal order, truncated to 125,000 bytes (3,907 digests; 1,000 bits per
stream are already available after 32 digests, the domain holds 393,216 per
instance). The digest is the cryptographic object the scheme's Step-1 keystream
rests on; its first four bytes are what the cipher reduces to a rotation offset
(Category 5 records that reduction separately).

### 3. `block_r1` — cryptographic component

Stream *i* concatenates the full 768 × 32 bytes of `HMAC-SHA256(Kr1_c,
b"r1" ∥ u16be(bid))` digests for each of 6 disjoint instances (indices
`101 + 6(i−1) … 106 + 6(i−1)`), i.e. 147,456 bytes, truncated to 125,000. Six
instances are required because one UserKey yields only 3 × 256 = 768 derivations;
the instances are disjoint so the stream is never a repetition of a shorter one.

### 4. `auth_tag` — cryptographic component

Stream *i* collects the 192 authentic HMAC-SHA256 group authentication codes of
each of 21 disjoint `(UserKey, ImageID)` instances computed over 21 distinct real
images (see above). Each code is `HMAC-SHA256(Kgroup, M)` where
`Kgroup = HMAC-SHA256(Kauth, ImageID ∥ channel_u8 ∥ Bid0…3_u16be)`,
`M` is the concatenation of the four Step-1 blocks (4,096 bytes, row-major) plus
`ImageID` and the ordered block identifiers, and `Kauth = HMAC-SHA256(UserKey,
b"auth")`. 21 × 192 × 32 = 129,024 bytes, truncated to 125,000. The Step-1
blocks are produced by the genuine revised Step-1 transform of the image.

### 5. `reduced_shift_diag` — diagnostic (not a randomness requirement)

Stream *i* records the **actual reduced Step-1 rotation offsets** used when
encrypting image *i*, one byte per pair (`offset ∈ [0, class_size)`, always
≤ 255), in the authentic traversal order, truncated to 125,000 bytes. This
category exists to document that the offsets are uniform *within each sum class*
(chi-square evidence in `output/metrics/class_uniformity.csv`) while a
byte-packing of them cannot be uniform over `0…255` because class sizes differ
(1 … 256). Failures here are expected and are not a defect of the keystream.

### 6. `ciphertext_diag` — diagnostic

Stream *i* is the first 125,000 bytes of the actual encrypted (marked) image
produced by `protect_image` for image *i* under instance `(UserKey_{2900+i},
ImageID_{2900+i})`. Mode (group / whole-image) and pairs used are recorded per
stream. A thumbnail-preserving ciphertext deliberately retains block sums, so it
is not a pseudorandom bit string and is **not** a randomness claim.

### 7. `recovered_diag` — diagnostic

Stream *i* is the first 125,000 bytes of the image returned after successful
authentication and exact recovery for the same 100 images (independent instance
range 3001 – 3100). The recovery is asserted bit-exact for every stream before
the stream is written. This is plaintext and is reported as a diagnostic only.

## Independence and non-repetition checks

`output/independence_checks.json` records, and `tests/test_atpe_v2.py` re-checks
against the real artifacts:

* 700 streams, 700,000,000 bits total;
* every stream SHA-256 distinct (`duplicate_stream_count = 0`), in every
  category and across categories;
* every ASCII expansion SHA-256 distinct;
* key/ImageID index partition disjoint and complete;
* no image repeats inside an `auth_tag` stream; the 100 diagnostic images are
  pairwise distinct; the image-reuse map is recorded;
* the revision activation status of the cipher used to produce the streams.

## Reproducing

```bash
python experiments/run_protocol.py --sts-dir <NIST_STS_2_1_2_ROOT> --parallel 4
python experiments/run_metrics.py
python -m pytest tests -q
```

Regenerating the streams reproduces every SHA-256 in
`output/stream_manifest.csv` exactly; the manifest also records the retrieval
source of each image and the digests of the image cache.