# Authenticated-TPE NIST output

This directory contains separate NIST SP 800-22 evaluation of authenticated-TPE cryptographic components and image-output diagnostics. Read [`NIST_AUTHENTICATED_TPE_REPORT.md`](NIST_AUTHENTICATED_TPE_REPORT.md) or its [`PDF companion`](NIST_AUTHENTICATED_TPE_REPORT.pdf) first. The Authentication-tag stream concatenates actual raw 256-bit HMAC group tags generated under independent keys and ImageIDs; the raw tag length is not misrepresented as 1,000,000 bits.

Individual first-level p-values with 17 significant digits are in [`results.csv`](results.csv) and [`p_values_full_precision.csv`](p_values_full_precision.csv); second-level uniformity p-values are in these files and [`per_test_summary.csv`](per_test_summary.csv). Original unmodified six-decimal output is preserved under `official_native_6dp/`. `raw_streams/` contains the exact packed binary inputs; `raw_reports/` holds the complete higher-precision STS rerun.

[`authentication_tag_sample_digests.csv`](authentication_tag_sample_digests.csv) gives an auditable SHA-256 digest for one actual raw 256-bit authentication tag from each of 100 independent key/ImageID cases.

No overall NIST pass or security proof is claimed. The image output is expected to retain image structure. All image data is from six available UCT images; no CelebA-HQ images are claimed.
