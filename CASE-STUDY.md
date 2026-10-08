# EP-AEC: independent verification and maintainer review

Marcus Richards · Python · protocol verification · regression testing

## Summary

Built an independent, revision-pinned EP-AEC verifier; documented a historical specification defect and incorporated maintainer feedback into a CLI regression. The maintainer independently reran all 64 tests and closed the issue.

[Source repository](https://github.com/marsojuji-cmyk/ep-aec-conformance) · [Review thread and resolution](https://github.com/emiliaprotocol/emilia-protocol/issues/864)

## The problem

In draft -02, a presenter-controlled component label could satisfy a requirement for a component type. A delegation receipt labelled `ep-quorum` could therefore satisfy a requirement for human authorization without supplying that authorization.

The maintainer confirmed the defect in the -02 text and clarified that draft -03 had already corrected it. The rule remains corrected in -07, and the current JavaScript verifier excludes labels from the satisfied type set. This work documented a historical specification defect; it did not discover a new vulnerability in the current verifier or cause the earlier specification correction.

[Maintainer's assessment](https://github.com/emiliaprotocol/emilia-protocol/issues/864#issuecomment-5976547044)

## Implementation and review

The Python verifier preserves -02 semantics for historical reproduction and supports selected -07 regression cases. Historical effect-attestation and ceremony-evidence vectors remain identified as -02-only because those definitions were removed from AEC in -03.

After pulling the published source, the maintainer found that the library forwarded the selected revision correctly but the CLI dropped `spec_revision` from the policy file. The CLI therefore used -02 rules even when the policy selected -07.

The correction forwards that field into `Policy`. Regression J8 runs the same labelled delegation chain through the CLI with two policy files: it must return ALLOW under -02 and DENY under -07. The maintainer supplied a failing-first regression, which was incorporated into the suite.

[CLI review](https://github.com/emiliaprotocol/emilia-protocol/issues/864#issuecomment-5977055967) · [Correction and regression, commit 51380ff](https://github.com/marsojuji-cmyk/ep-aec-conformance/commit/51380ff)

## Outcome

The maintainer reran commit `d583638`, reported all 64 tests passing, confirmed J8's revision-dependent CLI behavior without a crash, and closed #864. A final README correction replaced a broken standalone-runner instruction with `python3 -m pytest tests/test_conformance.py -v`.

[Independent rerun and closure confirmation](https://github.com/emiliaprotocol/emilia-protocol/issues/864#issuecomment-5977316516) · [README correction](https://github.com/marsojuji-cmyk/ep-aec-conformance/pull/1)

## Scope and limits

- The suite contains 56 historical -02 vectors and 8 selected -07 regressions. It is not full -07 conformance.
- The -07 port does not yet take the relying party's expected action and still requires the presenter requirement field that -07 makes optional.
- The four adversarial probes reproduce historical -02 findings; they do not establish four current vulnerabilities.
- The maintainer's independent rerun is evidence about the published tests and this issue's resolution, not a certification, comprehensive security audit, or endorsement of other projects.

## Application-ready description

> Developed a revision-pinned Python verifier for EP-AEC, documented a historical authorization-specification defect, and incorporated maintainer feedback into a CLI regression; the maintainer independently reproduced all 64 passing tests and closed the issue.

The public thread records both the finding and the correction to this implementation. Readers can inspect the source, the regression, and the maintainer's response rather than relying on a portfolio claim alone.
