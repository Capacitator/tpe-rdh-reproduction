# Sources for interpreting NIST SP 800-22 results

## NIST SP 800-22 Rev. 1a

Source: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf

NIST §4.2.1 defines the expected first-level pass proportion `p̂ = 1 − α` and an approximate 3-standard-deviation lower confidence bound `p̂ − 3 sqrt(p̂(1−p̂)/m)`, where `m` is the number of sequences. At `α=0.01`, `m=100`, the lower bound is approximately 0.96056 (96.06%). NIST §4.2.2 says the ten-bin chi-square uniformity p-value is acceptable at **≥ 0.0001**, and recommends at least 55 sequences.

The campaign's first-level decision threshold remains the requested `α=0.01`. The second-level uniformity check must use NIST's separate `0.0001` threshold. A p-value below 0.01 but above 0.0001 should not be reported as an official second-level failure.

## Independent interpretation discussion

Source: https://crocs.fi.muni.cz/lib/exe/fetch.php?media=public:research:romjist_v11_for_publish.pdf

Search-result and extraction evidence identify this as an independent discussion of interpreting NIST STS output, including the 0.0001 uniformity criterion. The primary threshold claim above is sourced to NIST SP 800-22 itself.
