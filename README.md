# EP-AEC Conformance Verifier

**This verifier checks IETF EP-AEC authorization evidence chains, built from the spec text alone. It fails closed on every error, and building it exposed a spec-level bypass.**

[![CI](https://github.com/marsojuji-cmyk/ep-aec-conformance/actions/workflows/ci.yml/badge.svg)](https://github.com/marsojuji-cmyk/ep-aec-conformance/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](pyproject.toml)

**Spec-first, not implementation-first.** The verifier is an independent implementation of `draft-schrock-ep-authorization-evidence-chain`, written from the specification text with no reference to the author's implementations. **Revision-pinned:** by default it implements **-02**, where all findings reproduce. `spec_revision="07"` selects current-draft semantics (labels display-only, chain requirement descriptive-only, §8 grammar). Live discussion: [emiliaprotocol/emilia-protocol#864](https://github.com/emiliaprotocol/emilia-protocol/issues/864).

## What it found

Building from the spec text alone exposed **one security-relevant bypass in the spec** (P1 / I1):

> **§4 step 3.4 puts `label` in the satisfied set alongside `type`. §5 resolves `IDENT` against both.** A presenter holding one delegation receipt and no human authorization can satisfy `delegation AND ep-quorum` by labelling the receipt `"ep-quorum"`. Same receipt, same signature, one string decides it.

Full write-up: [`results/CONFORMANCE-REPORT-2026-09-26.md`](results/CONFORMANCE-REPORT-2026-09-26.md).

## What it guarantees

- **Fails closed at every step.** Any unexpected error, malformed return, missing digest, malformed requirement expression, or unsafe action yields DENY (§4 step 5). Five vectors assert this (§4.5).
- **Rejects an unknown spec revision** with `ValueError` instead of silently defaulting (`epaec.py`).
- **Rejects cross-bound receipts.** A valid receipt for a different action returns DENY (§4.3.3).
- **Canonicalizes per RFC 8785** with I-JSON restrictions, and rejects duplicate keys.
- **Offline and stateless.** No network, no persistence, no daemons.

## Quickstart

```bash
pip install -e ".[dev]"
python3 -m pytest tests/test_conformance.py -v   # 64 vectors: 56 (-02) + 8 selected -07 regressions (section J)
python3 verifier/probe.py                        # 4 adversarial probes
```

The only runtime dependency is `PyNaCl`. Pass `spec_revision="07"` (or `Policy(spec_revision="07")`, or `"spec_revision": "07"` in a CLI policy file) for current-draft semantics.

## How it fails

| Input | Result |
|---|---|
| Verifier raises, or returns a malformed result | DENY |
| Missing version, digest mismatch, empty components, no verifier | DENY (§4 structure) |
| Unknown identifier in a requirement expression | evaluates to false (§5) |
| Invalid §8 effect-attestation signature, unpinned key, observed ≠ committed | DENY |
| §9 ceremony telemetry below floor, unusable, or badly signed | DENY |

**Known limits, stated plainly:**
- The 8 section-J vectors are selected -07 regressions, not full -07 conformance.
- In -07 mode the port does not yet take the relying party's expected action, and it still requires the presenter requirement field that -07 makes optional.
- Sections F (§8 effect attestation) and G (§9 ceremony evidence) are **-02-only**. AEC removed those definitions in -03. They are kept byte-identical and clearly separated.

## Coverage

| Section | Coverage | Vectors |
|---|---|---|
| §2 RFC 8785 JCS | UTF-16 ordering, escaping, safe integers, float normalization, nesting bound, duplicate rejection | 14 |
| §5 Requirements | strict LTR, equal precedence, parens, unknown → false | 5 |
| §4 Structure | missing version, digest mismatch, empty components, no verifier | 6 |
| §4.3.3 Cross-binding | valid receipt for a different action → DENY | 1 |
| §6 Precedence | presenter weak bar passes unpinned, pinned bar correctly fails | 3 |
| §8 Effect attestation (-02) | signature invalid, key unpinned, observed≠committed, no committed, pin precedence, prefix stripping, cross-binding | 13 |
| §9 Ceremony evidence (-02) | above/below floor, unusable telemetry, bad signature, no floor | 8 |
| §4.5 Fail-closed | verifier raises, malformed return, no digest, malformed expression, unsafe action | 5 |
| I1 Spec defect | label/type collision bypass | 1 |
| J -07 regressions | selected current-draft semantics | 8 |

**Adversarial probes:** `verifier/probe.py` runs 4 probes that produce 4 findings.
1. P1: a presenter-controlled label satisfies a required component type.
2. P2: the cross-binding defense is only as strong as each component's signature coverage.
3. P3: §3's own example label is unreferenceable by §5's grammar.
4. P4: conformant left-to-right evaluation diverges from conventional precedence.

## Evidence

- **64 tests pass:** `python3 -m pytest tests/test_conformance.py`, run 2026-10-07 on `main`. CI runs the same command on every push.
- **4 probes, 4 findings:** `python3 verifier/probe.py`, run 2026-10-07.
- Raw outputs are committed: `results/conformance-run-{01,02}.json`, `results/probe-run-{01,02}.json`, and logs.

## Architecture

```
verifier/
├── __init__.py        # public API: verify_chain, Policy, ComponentRegistry
├── epaec.py           # §2–§6 verification algorithm (fail-closed)
├── jcs.py             # RFC 8785 JSON Canonicalization (I-JSON restricted)
├── components.py      # §8 effect attestation + §9 ceremony evidence verifiers
├── fixtures.py        # shared test fixtures (keys, helpers, actions)
└── probe.py           # adversarial probes

tests/test_conformance.py                 # 64 conformance vectors (pytest)
results/CONFORMANCE-REPORT-2026-09-26.md  # the report
results/ERRATA-AND-SUBMISSION-2026-09-26.md
```

## Status

The -02 implementation is complete, with all 56 vectors passing. -07 support is partial (see Known limits). The finding is under discussion upstream in [#864](https://github.com/emiliaprotocol/emilia-protocol/issues/864). The verifier makes no novelty claims: EP-AEC is the draft author's work, and this repo reports a conformance result about it.

## License

MIT. See [LICENSE](LICENSE).

Target specification: `draft-schrock-ep-authorization-evidence-chain-02` by the EMILIA Protocol project. This implementation is independent and unaffiliated.
