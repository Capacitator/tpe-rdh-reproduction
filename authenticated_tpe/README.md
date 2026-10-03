# Authenticated TPE paper prototype

This is an independent implementation of the professor-provided reversible
block-group authentication method using pair-sum-preserving TPE, reversible
contrast mapping, and HMAC-SHA256. It does not import the original chaotic
TPE/RDH `pipeline.py`.

## Shared image fixtures

Experiments read the six tracked UCT color TIFF files from
`../tpe_rdh_reproduction/input/uct_colour/`. That directory is a read-only
fixture dependency; this subproject does not copy or modify those images. The
two 256x256 images are resized to 512x512 by the experiment script; the resize
filter is not explicitly set by the script. Preprocessing is recorded with each
run.

## Setup and commands

From the repository root, using the repository virtual environment:

```bash
.venv/bin/python -m pytest authenticated_tpe/tests -q
.venv/bin/python authenticated_tpe/experiments/run_authenticated_tpe.py
.venv/bin/python authenticated_tpe/experiments/check_authenticated_tpe_tampering.py
```

The dependencies are listed in `tpe_rdh_reproduction/requirements.txt` and
can be installed into a virtual environment with:

```bash
python -m pip install -r tpe_rdh_reproduction/requirements.txt
```

The experiment uses public deterministic test key and ImageID fixtures. They
are not production secrets. Production ImageIDs must be generated with the OS
CSPRNG, kept privately by the owner, and never reused. See
[`docs/AUTHENTICATED_TPE.md`](docs/AUTHENTICATED_TPE.md) for algorithm details
and limitations.

Test and experiment outcomes are under `output/`. They are prototype results,
not the professor's Colab notebook outputs, and do not constitute a formal
security proof or independent cryptanalysis.

## Reports

- [Authenticated-TPE report](reports/AUTHENTICATED_TPE_REPORT.md)
- [Authenticated-TPE executive summary](reports/EXECUTIVE_SUMMARY.md)
- [Comparison with the original project](../reports/COMPARISON.md)
