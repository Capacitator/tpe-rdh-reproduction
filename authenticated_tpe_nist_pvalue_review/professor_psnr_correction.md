# Draft to Professor: Correction to encrypted-image PSNR

**Subject:** Correction to PSNR reported for the authentication-marked encrypted image

Dear Professor,

I rechecked the PSNR reported for the encrypted image containing the authentication information. I found that the earlier value (27.7714 dB for Baboon) was calculated with the wrong reference image. The code compared the final authentication-marked image with the Step-2 encrypted image immediately before the authentication tag was embedded. That measures the distortion added by tag embedding; it is not the PSNR of the final encrypted image relative to the original image.

I corrected the metric to compare the **original 512 × 512 RGB input** against the **final encrypted image containing the authentication information**. PSNR is calculated over all RGB samples using `10 log10(255² / MSE)`. The earlier marking-only measure is retained separately and labelled “marked vs. Step-2 distortion,” so the two comparisons are no longer conflated.

| Image | Original vs. final authentication-marked ciphertext PSNR (dB) | SSIM |
|---|---:|---:|
| Airplane | 17.5464 | 0.3087 |
| Baboon | 17.2877 | 0.4941 |
| Couple | 25.4119 | 0.6784 |
| Girl | 22.5926 | 0.5000 |
| Lena | 18.1882 | 0.3126 |
| Peppers | 19.5001 | 0.3800 |
| **Arithmetic mean** | **20.0878** | **0.4457** |

For comparison, in the repeatable Baboon run the final marked image versus the pre-mark Step-2 image gives 27.7176 dB (SSIM 0.9629). This is tag-marking distortion, not input-to-encrypted-image fidelity, and is not a replacement for the corrected 17.2877 dB input-to-final value. The small difference from the previously reported 27.7714 dB is retained as a discrepancy between runs; I do not treat either marking-only value as the corrected image-fidelity score.

The correction changed the PSNR reference arrays and the metric labels, not the encryption/authentication algorithm, image inputs, keys, identifiers, or parameters. All six clean images still authenticate and recover exactly. I added a regression test for the metric reference and generated a new Word report without overwriting the earlier reports.

The corrected values describe this implementation and these six test images. They should not be presented as a reproduction of a paper’s exact PSNR unless its image fixtures, preprocessing, and reference-image definition are matched; the paper PDF and the referenced example image were not available in the workspace used for this check.

Sincerely,

[Your name]
