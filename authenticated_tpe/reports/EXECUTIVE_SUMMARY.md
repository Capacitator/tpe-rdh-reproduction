# Executive summary: authenticated-TPE prototype

## Implemented and tested

The project implements the professor-specific reversible block-group authentication method using pair-sum-preserving TPE, RCM, HMAC-SHA256, and four-block groups. It is an independent implementation, not an extension of the original chaotic algorithm.

- Authenticated-project tests: **19 passed in 45.42s**.
- Clean artifact cases that both verify and recover exactly: **7/7**.
- Tamper/credential cases rejected without plaintext: **7/7**.
- Whole-image fallback has a sufficient recorded capacity: **True**.
- The independent tampering script passed.

## Limitations and final status

The implementation uses documented conventions and deterministic public fixtures. A constructed case exercises fallback; the professor's external notebook and full attack study were unavailable. This is finite prototype evaluation, not a formal security proof.

> The paper-specific authenticated-TPE prototype passes the documented clean-recovery, authentication, tamper-rejection, wrong-key, wrong-ImageID, and whole-image-fallback tests under the stated parameters. These finite prototype tests do not constitute a formal security proof or complete reproduction of unavailable external attack notebooks.

Final status: documented prototype validation complete; the unavailable external notebook and attack study were not reproduced.

## Provenance

Branch `authenticated-tpe-paper`, source commit `ec2661b690fa544b32b4d785fca3da46dc5a9603`; report-generation worktree state: `dirty`. See [the detailed report](AUTHENTICATED_TPE_REPORT.md) for dependencies, input hashes, exact commands, artifact paths, and specification hash.
