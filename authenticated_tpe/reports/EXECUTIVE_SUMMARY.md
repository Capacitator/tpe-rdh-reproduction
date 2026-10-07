# Executive summary: authenticated-TPE prototype

The evaluation uses six public UCT images because the eight CelebA-HQ source files were unavailable. Authenticated-TPE is implemented with a fixed 32×32 block size; authenticated 8×8 and 16×16 results are therefore not reported.

## Implemented and tested

The project implements the professor-specific reversible block-group authentication method using pair-sum-preserving TPE, RCM, HMAC-SHA256, and four-block groups. It is an independent implementation, not an extension of the original chaotic algorithm.

- Authenticated-project tests: **28 passed in 50.28s**. The independent clean/tamper check also passed, including wrong-key and wrong-ImageID rejection.
- Natural UCT clean cases that both verify and recover exactly: **6/6**. A constructed fallback fixture is tracked separately.
- Tamper/credential cases rejected without plaintext: **7/7**.
- Whole-image fallback has a sufficient recorded capacity: **True**.
- The independent tampering script passed.

## Limitations and final status

The implementation uses documented conventions and deterministic public fixtures. A constructed case exercises fallback; the professor's external notebook and full attack study were unavailable. This is finite prototype evaluation, not a formal security proof.

> The paper-specific authenticated-TPE prototype passes the documented clean-recovery, authentication, tamper-rejection, wrong-key, wrong-ImageID, and whole-image-fallback tests under the stated parameters. These finite prototype tests do not constitute a formal security proof or complete reproduction of unavailable external attack notebooks.

Final status: documented prototype validation complete; the unavailable external notebook and attack study were not reproduced.

## Provenance

Branch `authenticated-tpe-paper`, source commit `08b16e6c03c84f3bf5b3175c1648413bc38d461f`; report-generation worktree state: `dirty`. See [the detailed report](AUTHENTICATED_TPE_REPORT.md) for dependencies, input hashes, exact commands, artifact paths, and specification hash.


Current six-image clean means (file I/O excluded): protection 1.807610542 s; verification 2.012549625 s; marked-vs-Step-2 PSNR 29.631940 dB; marked-vs-Step-2 SSIM 0.958737301. Exact CelebA-HQ inputs are unavailable; this is an adapted six-image UCT result.
