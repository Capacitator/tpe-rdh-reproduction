# Independent interpretation of the NIST p-values

This review reads the already-generated official NIST STS CSVs. It does not alter the cipher, regenerate data, select streams, or rewrite the original NIST reports.

## Bottom line

The cryptographic-component results are broadly consistent with the null expectation: 70,692/71,456 valid first-level values pass at α=0.01 (98.931%; expected about 99%), and 0/752 second-level uniformity values fail NIST's separate 0.0001 criterion. Their minimum second-level uniformity p-value is 0.000199129.

There are 7 cryptographic second-level p-values below 0.01, but **none is below NIST's 0.0001 uniformity threshold**. Treating every second-level p<0.01 as an official failure was too strict; those are retained as an optional screening count, not an official fail count.

The NIST three-sigma first-level pass-proportion approximation flags 20/752 cryptographic test-components as below its lower bound; 17 are NonOverlappingTemplate components. Under exact one-sided binomial tests for excess first-level failures, followed by Holm correction across all 752 cryptographic components at familywise 0.01, 0 components remain significant. This is a cautionary diagnostic, not proof that every component is independent or that the cipher is secure.

The image-derived ciphertext/recovered-image diagnostics are **not** expected to behave as random streams. Their low p-values do not indicate that the cryptographic PRF or HMAC outputs failed; they reflect structured image/plaintext data and must stay separately labelled.

## Category results

| Category | Type | First-level pass/fail/N-A | Pass rate | Components below NIST approximate pass bound | Second-level values <0.0001 (NIST) | Second-level values <0.01 (exploratory) | Minimum second-level p |
|---|---|---:|---:|---:|---:|---:|---:|
| `hmac_drbg` | cryptographic-component | 17758/184/858 | 98.974% | 8 | 0/188 | 3/188 | 0.00204298965629 |
| `pair_shift` | cryptographic-component | 17811/183/806 | 98.983% | 2 | 0/188 | 2/188 | 0.00357703092676 |
| `block_r1` | cryptographic-component | 17684/180/936 | 98.992% | 4 | 0/188 | 0/188 | 0.01265042135 |
| `auth_tag` | cryptographic-component | 17439/217/1144 | 98.771% | 6 | 0/188 | 2/188 | 0.000199128574335 |
| `reduced_shift_diag` | image-diagnostic | 220/15980/2600 | 1.358% | 162 | 162/162 | 162/162 | 6.18680103239e-188 |
| `ciphertext_diag` | image-diagnostic | 1339/14861/2600 | 8.265% | 162 | 162/162 | 162/162 | 6.18680103239e-188 |
| `recovered_diag` | image-diagnostic | 470/15730/2600 | 2.901% | 162 | 162/162 | 162/162 | 6.18680103239e-188 |

## Actual NIST tests, by category

The following table reports the named tests (Frequency, Block Frequency, Runs, etc.), not image diagnostics. P/F/N-A is summed across a test's components (for example, 148 NonOverlappingTemplate templates). The second-level column uses NIST's 0.0001 criterion.

| Category | NIST test | First-level P/F/N-A | Pass rate | Second-level p < 0.0001 | Min second-level p |
|---|---|---:|---:|---:|---:|
| `hmac_drbg` | ApproximateEntropy | 98/2/0 | 98.00% | 0/1 | 0.997822862778 |
| `hmac_drbg` | BlockFrequency | 100/0/0 | 100.00% | 0/1 | 0.108790955194 |
| `hmac_drbg` | CumulativeSums | 198/2/0 | 99.00% | 0/2 | 0.181556631981 |
| `hmac_drbg` | FFT | 99/1/0 | 99.00% | 0/1 | 0.102525680214 |
| `hmac_drbg` | Frequency | 99/1/0 | 99.00% | 0/1 | 0.474985686648 |
| `hmac_drbg` | LinearComplexity | 97/3/0 | 97.00% | 0/1 | 0.019187597983 |
| `hmac_drbg` | LongestRun | 99/1/0 | 99.00% | 0/1 | 0.851382575357 |
| `hmac_drbg` | NonOverlappingTemplate | 14646/154/0 | 98.96% | 0/148 | 0.00204298965629 |
| `hmac_drbg` | OverlappingTemplate | 96/4/0 | 96.00% | 0/1 | 0.9558347256 |
| `hmac_drbg` | RandomExcursions | 534/2/264 | 99.63% | 0/8 | 0.186565974858 |
| `hmac_drbg` | RandomExcursionsVariant | 1202/4/594 | 99.67% | 0/18 | 0.00457273181818 |
| `hmac_drbg` | Rank | 97/3/0 | 97.00% | 0/1 | 0.574903423864 |
| `hmac_drbg` | Runs | 99/1/0 | 99.00% | 0/1 | 0.719746574824 |
| `hmac_drbg` | Serial | 194/6/0 | 97.00% | 0/2 | 0.202267685406 |
| `hmac_drbg` | Universal | 100/0/0 | 100.00% | 0/1 | 0.514123620231 |
| `pair_shift` | ApproximateEntropy | 99/1/0 | 99.00% | 0/1 | 0.574903423864 |
| `pair_shift` | BlockFrequency | 98/2/0 | 98.00% | 0/1 | 0.851382575357 |
| `pair_shift` | CumulativeSums | 200/0/0 | 100.00% | 0/2 | 0.554420435873 |
| `pair_shift` | FFT | 100/0/0 | 100.00% | 0/1 | 0.494391686482 |
| `pair_shift` | Frequency | 100/0/0 | 100.00% | 0/1 | 0.595548507284 |
| `pair_shift` | LinearComplexity | 97/3/0 | 97.00% | 0/1 | 0.657933306214 |
| `pair_shift` | LongestRun | 97/3/0 | 97.00% | 0/1 | 0.897762597121 |
| `pair_shift` | NonOverlappingTemplate | 14658/142/0 | 99.04% | 0/148 | 0.00498057463817 |
| `pair_shift` | OverlappingTemplate | 100/0/0 | 100.00% | 0/1 | 0.115386582589 |
| `pair_shift` | RandomExcursions | 543/9/248 | 98.37% | 0/8 | 0.00357703092676 |
| `pair_shift` | RandomExcursionsVariant | 1226/16/558 | 98.71% | 0/18 | 0.0212616594993 |
| `pair_shift` | Rank | 98/2/0 | 98.00% | 0/1 | 0.289667490388 |
| `pair_shift` | Runs | 100/0/0 | 100.00% | 0/1 | 0.53414621691 |
| `pair_shift` | Serial | 197/3/0 | 98.50% | 0/2 | 0.739918292095 |
| `pair_shift` | Universal | 98/2/0 | 98.00% | 0/1 | 0.41902116661 |
| `block_r1` | ApproximateEntropy | 100/0/0 | 100.00% | 0/1 | 0.851382575357 |
| `block_r1` | BlockFrequency | 100/0/0 | 100.00% | 0/1 | 0.883171378424 |
| `block_r1` | CumulativeSums | 199/1/0 | 99.50% | 0/2 | 0.616305224983 |
| `block_r1` | FFT | 98/2/0 | 98.00% | 0/1 | 0.514123620231 |
| `block_r1` | Frequency | 99/1/0 | 99.00% | 0/1 | 0.964294972685 |
| `block_r1` | LinearComplexity | 97/3/0 | 97.00% | 0/1 | 0.153763337796 |
| `block_r1` | LongestRun | 99/1/0 | 99.00% | 0/1 | 0.699312570866 |
| `block_r1` | NonOverlappingTemplate | 14639/161/0 | 98.91% | 0/148 | 0.019187597983 |
| `block_r1` | OverlappingTemplate | 99/1/0 | 99.00% | 0/1 | 0.153763337796 |
| `block_r1` | RandomExcursions | 508/4/288 | 99.22% | 0/8 | 0.0821774649475 |
| `block_r1` | RandomExcursionsVariant | 1149/3/648 | 99.74% | 0/18 | 0.01265042135 |
| `block_r1` | Rank | 100/0/0 | 100.00% | 0/1 | 0.699312570866 |
| `block_r1` | Runs | 99/1/0 | 99.00% | 0/1 | 0.0235450327708 |
| `block_r1` | Serial | 200/0/0 | 100.00% | 0/2 | 0.0628207206179 |
| `block_r1` | Universal | 98/2/0 | 98.00% | 0/1 | 0.53414621691 |
| `auth_tag` | ApproximateEntropy | 99/1/0 | 99.00% | 0/1 | 0.350485212323 |
| `auth_tag` | BlockFrequency | 100/0/0 | 100.00% | 0/1 | 0.213309305083 |
| `auth_tag` | CumulativeSums | 195/5/0 | 97.50% | 0/2 | 0.554420435873 |
| `auth_tag` | FFT | 100/0/0 | 100.00% | 0/1 | 0.946307673764 |
| `auth_tag` | Frequency | 97/3/0 | 97.00% | 0/1 | 0.554420435873 |
| `auth_tag` | LinearComplexity | 98/2/0 | 98.00% | 0/1 | 0.719746574824 |
| `auth_tag` | LongestRun | 98/2/0 | 98.00% | 0/1 | 0.108790955194 |
| `auth_tag` | NonOverlappingTemplate | 14631/169/0 | 98.86% | 0/148 | 0.000199128574335 |
| `auth_tag` | OverlappingTemplate | 98/2/0 | 98.00% | 0/1 | 0.474985686648 |
| `auth_tag` | RandomExcursions | 442/6/352 | 98.66% | 0/8 | 0.0155981001901 |
| `auth_tag` | RandomExcursionsVariant | 988/20/792 | 98.02% | 0/18 | 0.0117913926301 |
| `auth_tag` | Rank | 99/1/0 | 99.00% | 0/1 | 0.0329228217378 |
| `auth_tag` | Runs | 99/1/0 | 99.00% | 0/1 | 0.595548507284 |
| `auth_tag` | Serial | 197/3/0 | 98.50% | 0/2 | 0.262248754595 |
| `auth_tag` | Universal | 98/2/0 | 98.00% | 0/1 | 0.319083502143 |

First-level pass/fail/N-A totals are across every individual stream-test component in the category. The expected first-level failure fraction under the null is α=0.01; p-values are not supposed to be near 1 for every stream.

## What to do

Do not change code or parameters to push p-values upward. Keep all first-level failures and N/A outcomes. Report the correct NIST second-level 0.0001 criterion separately from the user-requested first-level α=0.01. If seeking stronger evidence, pre-register and generate a new independent campaign with more streams and unchanged definitions; use it as a replication, not as a replacement for this run. A genuine implementation defect would justify a code fix and an entirely new, fully disclosed run, but this review found no statistically adjusted component-level signal that by itself justifies changing the cryptographic construction.

## Method and source

For each first-level test component, the NIST approximate lower pass-proportion bound is `(1−α) − 3 sqrt((1−α) α / m)`, where `m=pass+fail` excludes N/A streams. We also test whether each component has an excess number of failures under `Binomial(m, α)` using a pre-specified lower-pass (upper-failure) tail, then Holm-adjust over the 752 cryptographic components at familywise α=0.01. This adjustment is supplementary; dependence among test types makes it inappropriate to interpret raw component tests independently.

NIST SP 800-22 Rev. 1a §4.2.1 defines the first-level pass-proportion interval. §4.2.2 says the second-level uniformity p-value should be at least 0.0001 and at least 55 sequences should be processed. This campaign uses 100 streams per cryptographic category.

See [SOURCES.md](SOURCES.md) for the source links. The detailed test-by-test table is in `output/nist_test_by_test.csv`; component-level calculations are in `output/cryptographic_component_proportions.csv`.
