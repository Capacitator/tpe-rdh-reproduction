# Comparison of the two TPE/RDH projects

## Purpose

This report maps two different algorithms. The authenticated method is not the original method with a small patch, the original method must not inherit authentication claims, and the authenticated method must not inherit original-method NIST or NPCR/UACI claims unless they are independently run. The numbers below summarize each project's own fixtures and definitions, not a head-to-head benchmark.

| Property | Original chaotic TPE/RDH | Authenticated-TPE prototype |
|---|---|---|
| Source paper | An et al. (2026), “A dual-mode thumbnail-preserving encryption scheme based on chaotic system and reversible data hiding,” DOI 10.1007/s44443-026-00479-y; original report, Paper and scope | Professor-supplied “Reversible Block-Group Authentication for Thumbnail-Preserving Encrypted Color Images Using Reversible Contrast Mapping and HMAC-SHA256”; source/spec hash in authenticated report, Method and scope |
| Algorithm | 2D-CSM chaotic streams, block permutation, histogram-shifting RDH, sum-preserving pair substitution; original report, Implementation | Keyed pair-sum-preserving TPE, smaller-pixel cyclic re-encryption, HMAC-derived four-block groups, RCM tag embedding; authenticated report, Method and scope |
| ImageID policy | Image-derived identifier diversifies image-bound parameters; same-key/different-image behavior is in original report, Validation results | Private 128-bit ID generated with OS CSPRNG and retained by owner in production. Experiments use deterministic public IDs; no uniqueness registry. Authenticated report, Method and scope / output provenance |
| Key hierarchy | Documented key-to-chaos derivation convention; original report, Implementation and assumptions | Domain-separated HMAC-SHA256 channel, TPE, block-shift, structure, group and image keys; authenticated report, Method and scope and `docs/AUTHENTICATED_TPE.md` |
| Thumbnail preservation | RDH can alter block sums; pair substitution preserves post-RDH block sums. Original report, thumbnail/block-sum results | Pair-sum-preserving stages and RCM marking; marked-image fidelity is measured against Step-2 ciphertext. Authenticated report, Clean authentication results |
| Reversibility | Exact image and embedded-payload recovery in listed original tests and experiments | Verify first, then recover exactly on valid authentication; authenticated report, clean-image results |
| RDH | Yes; histogram-shifting payload and metadata embedding. Original report, Implementation | No separate payload RDH; RCM embeds authentication tags. Authenticated report, Method and scope |
| HMAC authentication | Not implemented; no authentication claim. Original report, limitations | HMAC-SHA256 tags: 192 group tags in group mode or one image tag in fallback. Authenticated report, Method and scope / clean results |
| Tamper detection | No authentication-based tamper detection. Original report, limitations | Seven controlled tamper/credential cases rejected, no plaintext released. Authenticated report, Tampering and fallback; `output/tamper_results.csv` |
| Wrong-key behavior | Not an authentication test; same-key image diversification is not authenticated rejection. Original report, Validation results | Wrong UserKey rejected, no plaintext. Authenticated report, Tampering and fallback |
| NIST evaluation | STS 2.1.2 outputs: mixed results with substantial failures; original report, NIST SP 800-22 Rev. 1a | Not run for this project; authenticated report, Validation, provenance and limits |
| NPCR/UACI | Original Section 6 and key-sensitivity experiments only; exact definitions and ranges in original report, Validation results | Not run for this project; authenticated report, Validation, provenance and limits |
| Exact recovery | 24/24 UCT all-block runs and 16/16 Section 6 runs; original report, Validation results | Six natural-image group-mode cases and constructed fallback case; authenticated report, Clean authentication results and Tampering and fallback |
| Group localization | Not applicable; original method has no authentication groups | Three localized group-mode attacks reported 1, 2 and 2 affected groups; whole-image mode has no group localization. Authenticated report, Tampering and fallback |
| Whole-image fallback | Not applicable | If any group lacks capacity, discard provisional group marks and try a single whole-image tag; constructed fixture passed. Authenticated report, Tampering and fallback |
| Security claims | Functional and statistical diagnostics do not prove cryptographic security. Original report, limitations and NIST results | Prototype evaluation only; finite tests are not a formal proof or independent cryptanalysis. Authenticated report, Validation, provenance and limits |
| Limitations | Underspecified paper details use implementation choices; NIST results are mixed. Original report, assumptions and limitations | Professor's reference notebook/complete attack study unavailable; deterministic fixtures and constructed fallback; no independent cryptanalysis. Authenticated report, Validation, provenance and limits |
| Detailed report | [Original TPE/RDH report](../tpe_rdh_reproduction/reports/ORIGINAL_TPE_RDH_REPORT.md) | [Authenticated TPE report](../authenticated_tpe/reports/AUTHENTICATED_TPE_REPORT.md) |

## Reading the results

The original project's statistical tests assess selected generated bitstreams; its differential and correlation measurements use that implementation's own definitions and inputs. The authenticated project's central outcomes are tag verification, rejection behavior, capacity and exact recovery. A NIST pass count cannot be compared directly with a tag-rejection count. Authenticated-TPE PSNR measures RCM marking distortion against its Step-2 image.

The shared UCT source files provide some common image content, but processing is not fully matched. The authenticated project resizes couple and girl from 256 × 256 to 512 × 512; the original UCT experiment retains native dimensions. Experiments use different algorithms, settings, metrics and threat assumptions. Do not compare metrics across experiments unless images, parameters and metric definitions match. Each result in the table is labelled with its project report and experiment source.

## Repository boundaries

- Original source, tests, experiments, NIST validation and outputs belong under [`tpe_rdh_reproduction/`](../tpe_rdh_reproduction/README.md).
- Professor-specific source, tests, experiments, method notes and outputs belong under [`authenticated_tpe/`](../authenticated_tpe/README.md).
- Authenticated-TPE reads the original project's UCT images as shared read-only fixtures. It does not import the original chaotic pipeline.

## Detailed reports

- [Original chaotic TPE/RDH report](../tpe_rdh_reproduction/reports/ORIGINAL_TPE_RDH_REPORT.md)
- [Authenticated TPE report](../authenticated_tpe/reports/AUTHENTICATED_TPE_REPORT.md)
- [Original-project executive summary](../tpe_rdh_reproduction/reports/EXECUTIVE_SUMMARY.md)
- [Authenticated-project executive summary](../authenticated_tpe/reports/EXECUTIVE_SUMMARY.md)
