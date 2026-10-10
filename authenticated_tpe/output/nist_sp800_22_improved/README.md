# Authenticated-TPE NIST output

This directory contains separate NIST SP 800-22 evaluation of actual authenticated-TPE cryptographic components and image-output statistical diagnostics. Read [`NIST_AUTHENTICATED_TPE_REPORT.md`](NIST_AUTHENTICATED_TPE_REPORT.md) or its [`PDF companion`](NIST_AUTHENTICATED_TPE_REPORT.pdf) first. The raw 256-bit HMAC output is tested as the separate Authentication-tag stream category using unique key/ImageID fixtures.

Individual first-level p-values are in [`results.csv`](results.csv); second-level NIST uniformity p-values and pass proportions are in that CSV and [`per_test_summary.csv`](per_test_summary.csv). Native STS p-values are printed to six decimal places. `0.000000` is retained as rounded output and is not missing. `raw_streams/` holds the exact packed binary inputs; `raw_reports/` holds complete official NIST reports and raw test output.

No overall NIST pass or security proof is claimed. The image output is expected to retain image structure. All image data is from six available UCT images; no CelebA-HQ images are claimed.
