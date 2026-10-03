# Executive summary: authenticated TPE prototype

The professor-specific project implements reversible block-group authentication using pair-sum-preserving TPE, reversible contrast mapping and HMAC-SHA256. It is a separate implementation and does not use the original chaotic `pipeline.py`.

Across six shared UCT color fixtures, all cases used group mode, all 192 tags per image verified, and every image was recovered exactly. Seven controlled tampering or credential-mismatch cases were rejected without plaintext release. A constructed capacity case exercised whole-image fallback and its tampering rejection.

> The paper-specific authenticated-TPE prototype passes the documented clean-recovery, authentication, tamper-rejection, wrong-key, wrong-ImageID, and whole-image-fallback tests under the stated parameters. These finite prototype tests do not constitute a formal security proof or complete reproduction of unavailable external attack notebooks.

The authenticated-only suite passed 19 tests; the independent tampering script passed. Final status: prototype evaluation complete for the documented fixtures. The full method, measurements and caveats are in the [authenticated-TPE report](AUTHENTICATED_TPE_REPORT.md); run details are in [`../output/provenance.txt`](../output/provenance.txt).
