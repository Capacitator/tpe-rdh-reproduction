# Flowchart hybrid experiment

The old TPE stage produces a thumbnail-preserving block permutation/RDH carrier. The authenticated method applies its reversible pair Step-1/Step-2, HMAC-SHA256, HMAC-DRBG block grouping and RCM tag marking at that capacity-adequate carrier stage. The old TPE pair-sum-preserving substitution is applied as an outer reversible transform after RCM; decryption inverts it before HMAC verification. This ordering adjustment is required because the legacy substitution ciphertext has negative RCM net capacity (see CAPACITY_AUDIT.md). No original source code was overwritten.

PSNR is reported both on full-resolution RGB pixels (original vs encrypted; not the thumbnail-preservation score) and on rounded 32x32 block-average RGB thumbnails. The latter directly measures thumbnail fidelity. SSIM is reported for thumbnails. Identifiers and keys in this experiment are reproducible public test fixtures, not production secrets.
