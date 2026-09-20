# Key-Sensitivity NPCR/UACI

One-bit key-sensitivity check on the six UCT colour images.
For each run, the image, payload, image identifier, and block
size stay fixed. Only one bit of the 256-bit key is flipped.

This is not the paper's Section 6.8 plaintext-difference table.

Best RGB UACI in this sweep:
- image: `baboon.tif`
- block size: `64`
- RGB NPCR: `99.465815%`
- RGB UACI: `27.353162%`

Reference ideal values for an 8-bit random cipher are about
NPCR 99.6094% and UACI 33.4635%. So the result shows high
pixel-change rate, but UACI is still below ideal.

Regenerate with:

```bash
python experiments/key_sensitivity_npcr_uaci.py
```
