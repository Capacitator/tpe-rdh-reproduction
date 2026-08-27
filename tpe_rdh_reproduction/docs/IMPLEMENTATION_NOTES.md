# Implementation Notes

This document maps the paper's algorithmic steps to the current Python code and records the assumptions needed to make the reproduction executable.

## Paper Step To Code Mapping

| Paper step | Mathematical idea | Code |
|---|---|---|
| Sec. 4.1 Eq. (2) | Cubic map | `src/chaos.py::cubic_map` |
| Sec. 4.1 Eq. (3) | Sinusoidal map | `src/chaos.py::sinusoidal_map` |
| Sec. 4.1 Eq. (4) | Coupled 2D-CSM chaotic map | `src/chaos.py::csm_2d_step`, `generate_2d_csm` |
| Sec. 5.1 | Reshape chaotic sequences into `Upsilon_P` and `Upsilon_S` | `src/chaos.py::generate_upsilon_matrices` |
| Sec. 5.2 | Block-wise pixel permutation controlled by sorted `Upsilon_P` values | `src/permutation.py::permute_image_blocks`, `inverse_permute_image_blocks` |
| Sec. 5.3 and Eq. (1) | Histogram-shifting reversible data hiding | `src/rdh.py::embed_bits`, `extract_bits_and_recover` |
| Sec. 5.4 Eq. (6) | Chaotic pair offset `delta` | `src/substitution.py::chaotic_pair_delta` |
| Sec. 5.4 Eq. (7) | Pixel pair to same-sum index `eta` | `src/substitution.py::pair_to_index` |
| Sec. 5.4 Eq. (8) | Modular index encryption | `src/substitution.py::encrypt_pair` |
| Sec. 5.4 Eq. (9) | Same-sum pair count | `src/substitution.py::same_sum_pair_count` |
| Sec. 5.4 Eq. (10) | Same-sum index back to pixel pair | `src/substitution.py::index_to_pair` |
| Sec. 5.5 | Reverse substitution, extract/recover RDH, reverse permutation | `src/pipeline.py::decrypt_rgb_image` |

## Parameter Choices

Paper-stated example parameters:

```text
x0 = 0.3
y0 = 0.2
r1 = 50
r2 = 50
d = 255
```

Current reproduction/demo parameters:

```text
discard_count = 0
vartheta = 10000.0
block sizes used in experiments = 8, 16, 32, 64
default integration block size = 4 for small unit tests
final demo block size = 16
```

`vartheta=10000.0` is used because the paper's Fig. 4 examples appear to map values such as `0.7492 -> 7492`, which is consistent with multiplying by `10000`. This is recorded as an inference, not an explicit textual parameter.

## Important Assumptions

- The paper does not specify key-to-chaos conversion. Code receives chaotic parameters directly.
- The paper does not define `kappa_1`, `T`, `T_tau`, or `kappa_2` numerically. Code receives a single explicit `discard_count`.
- `Upsilon_P` and `Upsilon_S` are generated from the x/y sequences of one 2D-CSM run. The paper does not fully define the independence mechanism.
- Permutation sorts each flattened `Upsilon_P` block in stable ascending order and applies that index order to the flattened image block.
- Substitution pairs pixels and chaotic values in row-major flattened order.
- RDH metadata uses an explicit binary header because the paper does not define a parseable overhead/payload format.
- RDH excludes the first 16 top-row pixels from shifting/embedding because those pixels store P and Z in their LSBs.
- RGB RDH embeds the real payload in channel 0 only; channels 1 and 2 embed empty payloads so their metadata remains reversible.

## Unresolved Paper Ambiguities

- 256-bit key derivation.
- Exact `kappa_1`, `T`, `T_tau`, and `kappa_2` construction.
- Whether `Upsilon_P` and `Upsilon_S` are x/y outputs from one run, separate runs, or another split.
- Permutation sort direction and tie handling.
- Pixel/chaotic pairing order inside each block.
- Exact `vartheta` textual value.
- RDH metadata format, payload-length format, and coordinate encoding.
- Full RGB RDH policy.
- Exact Section 6.8 differential attack pixel/channel/direction procedure.

## Exact Recovery Strategy

Every reversible component is tested independently:

- chaotic generation is deterministic;
- permutation followed by inverse permutation recovers exact pixels;
- RDH extraction restores the exact carrier and exact payload;
- substitution followed by inverse substitution recovers exact pairs/channels;
- integrated encryption/decryption recovers exact RGB images.

The integration tests use `np.array_equal`, not visual comparison. Current tests also check boundary values, deterministic output, shape preservation, dtype preservation, payload recovery, and post-RDH block-sum preservation.
