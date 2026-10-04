# EP-AEC Conformance Verifier

Independent implementation of IETF EP-AEC (`draft-schrock-ep-authorization-evidence-chain`), built from the spec text alone. **Revision-pinned:** default behavior implements **-02** (all findings reproduce); `spec_revision="07"` implements the current draft (labels display-only, chain requirement descriptive-only, §8 grammar). Live discussion: [emiliaprotocol/emilia-protocol#864](https://github.com/emiliaprotocol/emilia-protocol/issues/864).

**What this is:** a Python verifier built from the spec text alone (no reference to the author's implementations), with 64 conformance vectors (56 × -02, 8 × selected -07 regressions in section J) and 4 adversarial probes. Sections F (§8 effect attestation) and G (§9 ceremony evidence) are **-02-only** vectors — those definitions were removed from AEC in -03, kept byte-identical and clearly separated. Prerequisite: `PyNaCl` (`pip install -r requirements.txt`). Known -07 gaps (not yet implemented, stated plainly): the port does not take the relying party's expected action, and still requires the presenter requirement field that -07 makes optional.

**What it found:** one security-relevant bypass in the spec text (F1 — presenter-controlled label satisfies a required component type). See [the report](results/CONFORMANCE-REPORT-2026-09-26.md).

---

## Quick start

```bash
pip install -e ".[dev]"
python3 -m pytest tests/test_conformance.py -v   # 64 vectors: 56 (-02) + 8 (selected -07 regressions, section J)
```

56 -02 vectors, all passing, plus 8 selected -07 regression vectors (section J, not full -07 conformance). Sections §2, §4, §5, §6, §8 (-02-only), §9 (-02-only), plus fail-closed behavior and one security-relevant spec-defect probe. Pass `spec_revision="07"` (or `Policy(spec_revision="07")`, or `"spec_revision": "07"` in a CLI policy file) for current-draft semantics.

## Adversarial probes

```bash
python3 verifier/probe.py
```

4 probes → 4 findings. The one that matters:

> **§4 step 3.4 puts `label` in the satisfied set alongside `type`. §5 resolves `IDENT` against both.** A presenter holding one delegation receipt and no human authorization can satisfy `delegation AND ep-quorum` by labelling the receipt `"ep-quorum"`. Same receipt, same signature, one string decides it.

## What this covers

| Section | Coverage | Vectors |
|---|---|---|
| §2 RFC 8785 JCS | UTF-16 ordering, escaping, safe integers, float normalization, nesting bound, duplicate rejection | 14 |
| §5 Requirements | strict LTR, equal precedence, parens, unknown → false | 5 |
| §4 Structure | missing version, digest mismatch, empty components, no verifier | 6 |
| §4.3.3 Cross-binding | valid receipt for a different action → DENY | 1 |
| §6 Precedence | presenter weak bar passes unpinned, pinned bar correctly fails | 3 |
| §8 Effect attestation | signature invalid, key unpinned, observed≠committed, no committed, pin precedence, prefix stripping, cross-binding | 13 |
| §9 Ceremony evidence | above/below floor, unusable telemetry, bad signature, no floor | 8 |
| §4.5 Fail-closed | verifier raises, malformed return, no digest, malformed expression, unsafe action | 5 |
| I1 Spec defect | label/type collision bypass | 1 |

## Architecture

```
verifier/
├── __init__.py        # public API: verify_chain, Policy, ComponentRegistry
├── epaec.py           # §2–§6 verification algorithm (fail-closed)
├── jcs.py             # RFC 8785 JSON Canonicalization (I-JSON restricted)
├── components.py      # §8 effect attestation + §9 ceremony evidence verifiers
├── fixtures.py        # shared test fixtures (keys, helpers, actions)
└── probe.py           # adversarial probes

tests/
└── test_conformance.py  # 56 conformance vectors (pytest-native)

results/
├── CONFORMANCE-REPORT-2026-09-26.md   # the report
├── ERRATA-AND-SUBMISSION-2026-09-26.md # submission draft + reconciliation items
├── conformance-run-{01,02}.json       # raw JSON output
├── probe-run-{01,02}.json             # probe JSON output
└── *.log                              # raw logs
```

## Design principles

- **Fail-closed everywhere.** Any unexpected error at any step yields DENY. §4 step 5.
- **No novelty claims.** EP-AEC is the draft author's work; this is a conformance result about it.
- **Offline, stateless, one command.** No network dependency, no persistence, no daemons.
- **Spec-first, not implementation-first.** Every test is written from the specification text, not from anyone's reference code.

## Reproducing the findings

```bash
# conformance vectors (64 tests: 56 -02 + 8 selected -07 regressions)
python3 -m pytest tests/test_conformance.py -v

# adversarial probes (4 probes, 4 findings)
python3 verifier/probe.py
```

Every input is printed in the logs. One machine, one command, one result.

## License

MIT

## Acknowledgments

Target specification: `draft-schrock-ep-authorization-evidence-chain-02` by the EMILIA Protocol project. This implementation is independent and unaffiliated.