# Authenticated-TPE evaluation results for conference report

The evaluation uses six public UCT images because the eight CelebA-HQ source files were unavailable. Authenticated-TPE is implemented with a fixed 32×32 block size; authenticated 8×8 and 16×16 results are therefore not reported.

The exact eight CelebA-HQ images in the supplied Word template were unavailable. These results use six public UCT fixtures and are an adapted experiment, not an exact reproduction. The authenticated-TPE implementation supports fixed 32×32 blocks only; authenticated 8×8/16×16 results are: **N/A — authenticated-TPE implementation supports fixed 32×32 blocks only.** This report uses only authenticated-TPE results.

## Clean-image results

Each case uses group mode with 192 HMAC-SHA256 tags of 256 bits each (49,152 total tag bits). Protection and verification timings exclude file I/O. Marked-vs-Step-2 PSNR/SSIM compare the final RCM-marked image against the Step-2 image before marking; they are fidelity measures, not security measures.

| Image | Mode | Tags | Pairs used | Protect (s) | Verify (s) | Marked-vs-Step-2 PSNR (dB) | Marked-vs-Step-2 SSIM |
|---|---|---:|---:|---:|---:|---:|---:|
| airplane | group | 192 | 54,422 | 1.801782667 | 1.982827250 | 30.197769 | 0.964932587 |
| baboon | group | 192 | 57,474 | 1.794341667 | 1.992045625 | 27.771427 | 0.963104519 |
| couple | group | 192 | 80,778 | 1.891289376 | 2.164496500 | 32.624797 | 0.965344652 |
| girl | group | 192 | 62,248 | 1.798324209 | 2.004182667 | 30.107185 | 0.953497455 |
| lena | group | 192 | 55,012 | 1.765184042 | 1.952447917 | 28.060002 | 0.951909622 |
| peppers | group | 192 | 57,422 | 1.794741292 | 1.979297791 | 29.030458 | 0.953634973 |

## Recovery and authentication verification

Metrics were verified from the actual processed source and recovered RGB arrays. All six rows authenticated and recovered exactly.

| Image | Authentication verified | Exact recovery | Recovered MSE | Maximum error | Recovered PSNR (dB) | Recovered SSIM |
|---|---|---|---:|---:|---:|---:|
| airplane | True | True | 0.000000000 | 0 | inf | 1.000000000 |
| baboon | True | True | 0.000000000 | 0 | inf | 1.000000000 |
| couple | True | True | 0.000000000 | 0 | inf | 1.000000000 |
| girl | True | True | 0.000000000 | 0 | inf | 1.000000000 |
| lena | True | True | 0.000000000 | 0 | inf | 1.000000000 |
| peppers | True | True | 0.000000000 | 0 | inf | 1.000000000 |

## Final-marked image entropy

Shannon entropy uses H = −Σ p(i) log₂ p(i), computed from 256-bin uint8 histograms. R, G, and B are separate channels; RGB pooled combines all three channel samples. Values were recomputed from the final marked RGB arrays and match the existing entropy results CSV.

| Image | R (bits) | G (bits) | B (bits) | RGB pooled (bits) |
|---|---:|---:|---:|---:|
| airplane | 7.135636527 | 7.180702424 | 6.784789838 | 7.064999369 |
| baboon | 7.807437634 | 7.683203666 | 7.842778310 | 7.854161678 |
| couple | 6.758240761 | 6.307566009 | 6.192004474 | 6.463652151 |
| girl | 7.428313126 | 7.077189296 | 6.942157102 | 7.231297119 |
| lena | 7.434802831 | 7.746658523 | 7.350288629 | 7.861728222 |
| peppers | 7.583238681 | 7.630465959 | 7.239497768 | 7.761418610 |

## Neighboring-pixel correlation

Per-channel RGB correlations compare each source image with its final marked image. Each value uses 5,000 sampled neighboring pairs per direction/channel and seed 20261006; these are not luminance correlations.

| Image | Direction | R original / marked | G original / marked | B original / marked |
|---|---|---:|---:|---:|
| airplane | horizontal | 0.972059263 / 0.529458784 | 0.957885230 / 0.594604467 | 0.963411626 / 0.430377300 |
| airplane | vertical | 0.956677114 / 0.606448356 | 0.968791461 / 0.669320572 | 0.937826871 / 0.482331255 |
| airplane | diagonal | 0.933178832 / 0.581114990 | 0.933977871 / 0.629571086 | 0.917522045 / 0.461943073 |
| baboon | horizontal | 0.925286787 / 0.566500542 | 0.865154013 / 0.506628076 | 0.906468800 / 0.629881713 |
| baboon | vertical | 0.872421334 / 0.585969519 | 0.766183164 / 0.551827602 | 0.881988168 / 0.681137856 |
| baboon | diagonal | 0.860776339 / 0.596071899 | 0.736580896 / 0.515929948 | 0.839695832 / 0.643800748 |
| couple | horizontal | 0.987360896 / 0.759833467 | 0.983070517 / 0.791854193 | 0.980513683 / 0.783577301 |
| couple | vertical | 0.988454083 / 0.839162256 | 0.987513980 / 0.842611254 | 0.985635217 / 0.860174463 |
| couple | diagonal | 0.977862878 / 0.812327268 | 0.973664793 / 0.818550699 | 0.968952980 / 0.818098357 |
| girl | horizontal | 0.993305982 / 0.720600545 | 0.993446091 / 0.784063738 | 0.990537645 / 0.772539365 |
| girl | vertical | 0.990551079 / 0.788123170 | 0.990850430 / 0.847416536 | 0.988112445 / 0.829625921 |
| girl | diagonal | 0.985139725 / 0.792164874 | 0.985105493 / 0.833618496 | 0.980838665 / 0.840222051 |
| lena | horizontal | 0.979653401 / 0.508080360 | 0.969412499 / 0.716384960 | 0.933489230 / 0.431461791 |
| lena | vertical | 0.990413729 / 0.590373583 | 0.983492763 / 0.805011931 | 0.958401964 / 0.575900160 |
| lena | diagonal | 0.970525384 / 0.582518390 | 0.956732903 / 0.771605673 | 0.916806037 / 0.570202946 |
| peppers | horizontal | 0.964900269 / 0.567517901 | 0.981697358 / 0.841458131 | 0.964297801 / 0.736775831 |
| peppers | vertical | 0.962945846 / 0.642732262 | 0.979478613 / 0.874507128 | 0.963988809 / 0.798898487 |
| peppers | diagonal | 0.956086720 / 0.668513026 | 0.966906804 / 0.857040882 | 0.945051041 / 0.780644823 |

## Authentication and capacity notes

The recorded attack/credential cases were rejected: 7/7; plaintext was released in 0/7 failed-authentication cases. The constructed whole-image fallback is separate from the six natural-image cases. Capacity details remain in `authenticated_tpe/output/capacity_results.csv`.

Existing NIST SP 800-22 results are unchanged and intentionally omitted from this handoff. SP 800-22 is a statistical diagnostic, not a cryptographic proof.
