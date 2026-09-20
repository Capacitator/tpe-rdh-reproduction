# Key-Sensitivity NPCR/UACI

This folder records a one-bit key-sensitivity check on the six UCT
colour images. For each image and block size, the experiment keeps
the plaintext image, payload, automatic image identifier, and all
parameters fixed, then flips one bit of the 256-bit key and compares
the two ciphertext images.

This is not the paper's Section 6.8 plaintext-differential table.

Best RGB UACI in this sweep:
- image: `baboon.tif`
- block size: `64`
- RGB NPCR: `99.465815%`
- RGB UACI: `27.353162%`

The ideal random 8-bit image-cipher reference is approximately
NPCR 99.6094% and UACI 33.4635%, so these results should be
reported as strong pixel-change sensitivity with moderate UACI,
not ideal avalanche behavior.

Regenerate with:

```bash
python experiments/key_sensitivity_npcr_uaci.py
```
