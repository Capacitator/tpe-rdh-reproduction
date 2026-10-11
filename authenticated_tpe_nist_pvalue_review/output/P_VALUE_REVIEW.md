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

First-level pass/fail/N-A totals are across every individual stream-test component in the category. The expected first-level failure fraction under the null is α=0.01; p-values are not supposed to be near 1 for every stream.

## What to do

Do not change code or parameters to push p-values upward. Keep all first-level failures and N/A outcomes. Report the correct NIST second-level 0.0001 criterion separately from the user-requested first-level α=0.01. If seeking stronger evidence, pre-register and generate a new independent campaign with more streams and unchanged definitions; use it as a replication, not as a replacement for this run. A genuine implementation defect would justify a code fix and an entirely new, fully disclosed run, but this review found no statistically adjusted component-level signal that by itself justifies changing the cryptographic construction.

## Method and source

For each first-level test component, the NIST approximate lower pass-proportion bound is `(1−α) − 3 sqrt((1−α) α / m)`, where `m=pass+fail` excludes N/A streams. We also test whether each component has an excess number of failures under `Binomial(m, α)` using a pre-specified lower-pass (upper-failure) tail, then Holm-adjust over the 752 cryptographic components at familywise α=0.01. This adjustment is supplementary; dependence among test types makes it inappropriate to interpret raw component tests independently.

NIST SP 800-22 Rev. 1a §4.2.1 defines the first-level pass-proportion interval. §4.2.2 says the second-level uniformity p-value should be at least 0.0001 and at least 55 sequences should be processed. This campaign uses 100 streams per cryptographic category.

See [SOURCES.md](SOURCES.md) for the source links. The detailed component-level calculations are in `output/cryptographic_component_proportions.csv`.
