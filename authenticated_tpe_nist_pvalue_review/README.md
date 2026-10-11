# Independent NIST p-value review

This folder is a separate, non-mutating review of the existing campaign. It does **not** modify the cipher or its 700 generated streams and does not rerun or replace any NIST results.

## Run

From this folder:

```bash
python3 review_pvalues.py
```

The script reads the immutable campaign CSVs from `../authenticated_tpe_nist_v2/output/` and writes:

- `output/P_VALUE_REVIEW.md` — interpretation and actionable conclusion;
- `output/category_interpretation.csv` — first-level, applicability and second-level counts by category;
- `output/cryptographic_component_proportions.csv` — component-level pass rates, NIST three-sigma lower bounds, exact binomial tail p-values and Holm adjustment.

Thresholds follow NIST SP 800-22 Rev. 1a: first-level α=0.01, the requested value; second-level uniformity p-value ≥0.0001, a separate NIST criterion. Sources and the exact section references are in `SOURCES.md`.

The review distinguishes cryptographic components from image-derived diagnostics. It does not tune p-values and does not claim that NIST STS establishes security.
