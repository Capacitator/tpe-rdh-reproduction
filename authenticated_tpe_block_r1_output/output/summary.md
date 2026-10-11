# Actual block-r1 output: NIST STS 2.1.2 results

Supplemental test of the actual two-bit `r1` values consumed by the cipher. It preserves the earlier full-HMAC-digest `block_r1` campaign; it does not replace those results or tune the algorithm.

## Protocol and integrity

- Official NIST STS 2.1.2 `assess`, all default tests, ASCII input, 100 streams × 1,000,000 bits, first-level α=0.01.
- Streams: 100; bytes per stream: 125,000; distinct stream hashes: 100; disjoint UserKey indices: 65200.
- First-level p-value entries: 18800 = 17630 pass, 156 fail, 1014 N/A. Valid p-value pass rate: 99.123% (expected approximately 99%).
- Second-level uniformity: 188 valid component p-values; 0 below NIST's 0.0001 criterion; minimum 0.000199128574335.
- NIST approximate three-sigma pass-proportion checks: 0/188 components below the lower bound; exact one-sided binomial tests with Holm correction at 0.01: 0/188 significant.
- Raw STS files in report manifest: 31; hash mismatches: 0. Input ASCII lines and stream sizes verified.
- N/A entries arise from NIST Random Excursions applicability conditions; see per-test N/A stream counts below. They are not discarded failures.

## Named NIST tests

| NIST test | First-level P/F/N-A | Valid pass rate | N/A streams | Second-level p-values | Below 0.0001 | Minimum second-level p |
|---|---:|---:|---:|---:|---:|---:|
| Frequency | 100/0/0 | 100.000% | 0 | 1 | 0 | 0.798139062395 |
| BlockFrequency | 99/1/0 | 99.000% | 0 | 1 | 0 | 0.616305224983 |
| CumulativeSums | 200/0/0 | 100.000% | 0 | 2 | 0 | 0.171866837467 |
| Runs | 100/0/0 | 100.000% | 0 | 1 | 0 | 0.350485212323 |
| LongestRun | 99/1/0 | 99.000% | 0 | 1 | 0 | 0.474985686648 |
| Rank | 98/2/0 | 98.000% | 0 | 1 | 0 | 0.595548507284 |
| FFT | 99/1/0 | 99.000% | 0 | 1 | 0 | 0.191686740847 |
| NonOverlappingTemplate | 14667/133/0 | 99.101% | 0 | 148 | 0 | 0.000199128574335 |
| OverlappingTemplate | 98/2/0 | 98.000% | 0 | 1 | 0 | 0.851382575357 |
| Universal | 99/1/0 | 99.000% | 0 | 1 | 0 | 0.181556631981 |
| ApproximateEntropy | 98/2/0 | 98.000% | 0 | 1 | 0 | 0.236809815218 |
| RandomExcursions | 483/5/312 | 98.975% | 39 | 8 | 0 | 0.311542340562 |
| RandomExcursionsVariant | 1093/5/702 | 99.545% | 39 | 18 | 0 | 0.0212616594993 |
| Serial | 197/3/0 | 98.500% | 0 | 2 | 0 | 0.0288171732613 |
| LinearComplexity | 100/0/0 | 100.000% | 0 | 1 | 0 | 0.883171378424 |

The P/F/N-A values are summed across components (e.g. 148 template components); for the two Random Excursions tests, N/A component counts are not N/A stream counts. First-level failures are retained. Second-level values below 0.01 but above 0.0001 are listed in `test_by_test_summary.csv` as exploratory-only and are not NIST uniformity failures.

## Interpretation

The actual `r1` component passed Frequency 100/100, Block Frequency 99/100, and Runs 100/100. Across all NIST components there are 156 first-level failures among 17,786 applicable p-values, which is not a reason to alter keys, bit packing, parameters, or outcomes. No stream was removed. All 188 second-level uniformity values exceed 0.0001. These tests do not establish cryptographic security.

The 0.000199 minimum uniformity p-value is close to but above the official 0.0001 cutoff. It is disclosed, not rounded into a failure or hidden. The test-by-test CSV, first-level p-values, second-level histograms, official raw reports, stream manifest and artifact hashes are retained under `output/`.
