# TPE/RDH research projects

This repository contains two separate projects:

- [`tpe_rdh_reproduction/`](tpe_rdh_reproduction/README.md) is the original chaotic TPE/RDH reproduction. Its source, tests, experiments, outputs, and NIST SP 800-22 run remain in that project.
- [`authenticated_tpe/`](authenticated_tpe/README.md) is the independent professor-specific RCM/HMAC authenticated-TPE implementation. It imports only the shared UCT image fixtures from the original project.

The authenticated method does not import or modify the original `pipeline.py`.
Each project has its own `src/`, `tests/`, `experiments/`, `docs/`, and output
area so their implementations and results remain distinct.

## Reports

- [Cross-project comparison](reports/COMPARISON.md)
- [Original-project report](tpe_rdh_reproduction/reports/ORIGINAL_TPE_RDH_REPORT.md)
- [Original-project executive summary](tpe_rdh_reproduction/reports/EXECUTIVE_SUMMARY.md)
- [Authenticated-TPE report](authenticated_tpe/reports/AUTHENTICATED_TPE_REPORT.md)
- [Authenticated-TPE executive summary](authenticated_tpe/reports/EXECUTIVE_SUMMARY.md)
