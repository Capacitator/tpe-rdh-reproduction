# Authenticated TPE experiment outputs

These are project prototype results from `experiments/run_authenticated_tpe.py`; they are not the professor PDF's Colab/reference results.
All key/ImageID values are deterministic test fixtures and must not be used in production.
ImageID values are deliberately omitted. Production ImageIDs are generated with a CSPRNG and retained privately by the owner.
See `docs/AUTHENTICATED_TPE.md` for method, encodings, assumptions, and limitations.

- `clean_authentication_results.csv`: clean mode, auth/recovery, pair count, fidelity and runtime.
- `tamper_results.csv`: one-bit, block, cross-channel, credential and replacement negative cases.
- `capacity_results.csv`: group prefix net capacity and whole-image net capacity.
- `key_derivation_vectors.txt`: explicit public test-vector outputs.
- `provenance.txt`: source commit, worktree state, versions, command and source hashes.
- `summary.txt`: compact result interpretation.
- `report.md`: full validation report, test interpretation, source notes, and limitations.
