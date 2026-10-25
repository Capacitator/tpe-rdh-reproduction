# Test results

Starting branch head: `32e6c4922c1fc624a0f3878294663ff97d6b35ef`.

- `python -m pytest authenticated_tpe_nist_v2/tests/test_four_pixel_authenticated_tpe.py -q`: **13 passed** in 27.27 s. Covers the four-pixel transform and pipeline, exact image/payload recovery, block sums, authentication, wrong keys/ID, tampering, cross-image blocks and group localization, including the omitted-key guard.
- `python -m pytest tpe_rdh_reproduction/tests -q`: **102 passed** in 80.64 s. 14 dependency deprecation warnings.
- `python -m pytest authenticated_tpe_nist_v2/tests -q`: **37 passed, 2 failed** in 124.67 s. `test_image_pool_is_distinct_and_normalised` fails because `/home/ubuntu/work/ucid/1.tif` is absent. `test_generated_streams_are_pairwise_distinct_and_hashed` fails because `authenticated_tpe_nist_v2/output/streams/hmac_drbg_001.bin` is absent while its manifest exists. These external input/omitted artifact prerequisites are not restored by this task.

No NIST SP 800-22 campaign was rerun for the v2 four-pixel adaptation. Existing schedule-stream reports were parsed independently; results are in `nist_independent_recount.json`.
