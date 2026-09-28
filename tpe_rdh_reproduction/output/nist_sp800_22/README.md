# NIST SP 800-22 Rev. 1a experiment

This directory contains generated results from the NIST Statistical Test Suite
(STS) 2.1.2, reference checkout `terrillmoore/NIST-Statistical-Test-Suite`.
The experiment uses its official `assess` executable; it does not use a
home-grown NIST score or substitute statistical test.

Run from the project root after downloading/building official NIST STS 2.1.2:

```bash
curl -L -o sts-2_1_2.zip https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip
unzip sts-2_1_2.zip
cd sts-2.1.2/sts-2.1.2
mkdir -p obj experiments/{AlgorithmTesting,BBS,CCG,G-SHA1,LCG,MODEXP,MS,QCG1,QCG2,XOR}
(cd experiments && bash ./create-dir-script)
make
cd /path/to/tpe_rdh_reproduction
python experiments/run_nist_sp800_22.py --sts-dir /path/to/sts-2.1.2/sts-2.1.2
```

Two categories are evaluated: `Upsilon_P` then `Upsilon_S` matrices, and final
encrypted RGB images. Ten deterministic streams per category contain exactly
1,000,000 bits each. Chaotic values use `floor((x+1)*128)` clipped to uint8;
ciphertext uses actual uint8 RGB pixels. Both are serialized row-major, bytes
are converted MSB first, and the first 1,000,000 bits are tested. The fixed
image order, key hex, and automatically derived image identifier are recorded
in `stream_manifest.csv`. The first two streams use the same key with different
images, preserving the automatic image-derived diversification behavior.

STS default parameters are used: significance level 0.01; Block Frequency
length 128; Non-overlapping and Overlapping Template lengths 9; Approximate
Entropy length 10; Serial length 16; Linear Complexity length 500. Other
parameters use STS 2.1.2 defaults. Native reports are preserved per category.
Results support only statements that selected streams passed selected tests
under these parameters. They do not prove cryptographic security and remain
distinct from NPCR, UACI, entropy, correlation, exact recovery, and
thumbnail-preservation metrics.

The experiment does not change encryption or key derivation. Documented paper
ambiguities around key-to-chaos conversion, image identifier hashing, `T_tau`,
`kappa_2`, RDH metadata, and `vartheta` remain implementation decisions or
inferences.

Generated files include `provenance.txt`, `stream_manifest.csv`, the exact
ASCII bitstream inputs, `results.csv`, category-specific native analysis
reports, and `summary.txt`. Per-test STS scratch logs are parsed during the run
and discarded after their values and applicability are captured. If STS cannot
be built or run, the experiment stops with an error; it never replaces the
suite with unrelated metrics.

## Sources and limitations

NIST is the authoritative source. The GitHub repository below is a practical
implementation reference only. Sources were accessed on 2026-09-28:

1. [Official NIST documentation and software](https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software)
2. [Official NIST SP 800-22 Rev. 1a PDF](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf)
3. [Official guide to the statistical tests](https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software/guide-to-the-statistical-tests)
4. [Official publication page](https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final), publication date 2010-04-30
5. [Official revision notice](https://csrc.nist.gov/news/2022/decision-to-revise-nist-sp-800-22-rev-1a), dated 2022-04-19
6. [Professor-provided practical implementation reference](https://github.com/terrillmoore/NIST-Statistical-Test-Suite)

SP 800-22 Rev. 1a provides statistical tests for random and pseudorandom
bitstreams. This suite is an additional statistical evaluation for this
project. Passing the tests does not prove that the encryption scheme is
cryptographically secure, and statistical testing is not a substitute for
cryptanalysis. NIST's April 19, 2022 revision notice says SP 800-22 Rev. 1a is
planned for revision and specifically calls for clarifying its use and
rejecting its use as an assessment of cryptographic random-number generators.
Therefore results are reported only as “passed/failed the selected statistical
tests under the stated parameters,” not “proved secure.” These results are
distinct from NPCR, UACI, entropy, correlation, exact-recovery, and
thumbnail-preservation metrics.
