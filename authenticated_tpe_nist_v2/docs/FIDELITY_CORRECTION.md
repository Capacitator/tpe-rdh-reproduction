# Image-fidelity correction

## Finding

A review confirmed the concern: the earlier v2 report called its 27.72 dB Baboon value **encrypted-image PSNR**, but the code actually compared the final marked ciphertext with the **Step-2 image immediately before authentication-tag embedding**. That number measures the extra distortion caused by embedding the tag into the encrypted image. It does **not** measure the fidelity of the encrypted image to the original image.

The relevant thumbnail/image-fidelity comparison is original plaintext input versus final encrypted/marked output. The algorithm itself was rechecked and not changed. The data pipeline independently constructs Step 1, Step 2 and final marking, and confirms the stored final output is exactly `protect_image(image, key, image_id).marked_image`. The earlier metric name/reference was wrong; the encryption was not tuned to improve its score.

## Corrected values

| Image | Original input vs final encrypted/marked: PSNR (dB) | SSIM | Final marked vs Step-2 pre-mark image: PSNR (dB) | SSIM |
|---|---:|---:|---:|---:|
| airplane | 17.5464 | 0.3087 | 30.1757 | 0.9660 |
| baboon | 17.2877 | 0.4941 | 27.7176 | 0.9629 |
| couple | 25.4119 | 0.6784 | 32.5139 | 0.9654 |
| girl | 22.5926 | 0.5000 | 30.0464 | 0.9537 |
| lena | 18.1882 | 0.3126 | 28.1002 | 0.9519 |
| peppers | 19.5001 | 0.3800 | 28.9772 | 0.9542 |

The first pair of columns is now called **input-vs-encrypted fidelity**. The second pair is explicitly **tag-marking distortion**. The old Baboon value 27.7714 dB and the earlier reproduction at 27.7 dB are near the latter quantity, not the former. They cannot be used to claim that the final ciphertext has that PSNR against the original image.

## Verification and interpretation

* The PSNR calculation uses the standard `10 log10(255² / MSE)` over all RGB samples, with the same 512×512 RGB input supplied to the encryption and the resulting final marked ciphertext.
* SSIM compares those exact same two arrays with `data_range=255` and RGB channel axis 2.
* The marking-only values remain in the results for traceability, but are no longer labelled as encrypted-image visual fidelity.
* Decryption remains exact for all six UCT fixtures; authentication still accepts all clean outputs.
* **No cipher primitive, parameter, input, key or identifier was changed.** The finding is a reporting/measurement reference bug. No p-value or PSNR was targeted or tuned.
* The original paper PDF and the image the user referred to were not present in the active workspace, so this corrects the metric definition and labels but does not assert that the first paper's exact input fixture or preprocessing has been matched. If its reported figure uses a different explicit reference pair, that source should be checked before claiming a numerical reproduction.

The corrected code is `experiments/run_metrics.py`; the values are in
`output/metrics/image_quality.csv`; the new report is
`output/report/authenticated_tpe_nist_v2_fidelity_correction.docx`. The earlier
report file is preserved rather than overwritten.
