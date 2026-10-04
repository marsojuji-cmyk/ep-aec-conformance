# EP-AEC Conformance Verifier — Grok.com Post

**Title:** Independent EP-AEC Conformance Verifier — 63 Vectors, 4 Findings, author-confirmed F1, -07 packet delivered

**Content:**

---

I built an independent conformance verifier for IETF EP-AEC from the spec text alone. The draft author just confirmed my headline finding and asked for a -07 packet. Here's the whole loop.

## What it does

Implements §2–§9 of the EP-AEC draft — the algorithm that lets a relying party verify heterogeneous agent-authorization receipts offline, with a single fail-closed ALLOW/DENY. **Revision-pinned:** default is -02 (all findings reproduce); `spec_revision="07"` implements the current draft.

## Current state

- 63 conformance vectors, all passing (56 × -02 + 7 × -07, section J)
- 4 adversarial probes, all reproducing (run in -02 mode)
- 35/35 EP-CANONICALIZATION-v1 battery pass
- Issue #864 OPEN — author replied, packet delivered, gist linked

## The headline: F1 confirmed by the author

§4 step 3.4 (in -02) let a presenter-controlled label satisfy a required component type. The author confirmed it as a real defect in the -02 text, fixed since -03; labels are display-only in -07 §3. My J1 vector pins the fixed behavior (attack now DENYs); the -02 vector keeps reproducing the original bypass.

## The packet (delivered)

- `conformance-run-03.json` (63/63) + `probe-run-03.json` (4/4) + one-command runner: https://gist.github.com/marsojuji-cmyk/30240a1084cdfc6d033c91827336d420
- Reply: https://github.com/emiliaprotocol/emilia-protocol/issues/864#issuecomment-5976831415
- Effect/ceremony vectors (F/G) explicitly marked -02-only — removed from AEC in -03, kept separate per the author's request

## How to reproduce (local tree — source not yet published, no install needed)

```bash
cd /Users/user/.hermes/profiles/darpa/workspace/receipt-conformance
python3 -m pytest tests/test_conformance.py -v   # 63 vectors
python3 verifier/probe.py             # 4 probes
```

## Method (transferable)

Implement from spec text alone → conformance vectors → adversarial probes (is the *spec* safe, not just the code?) → reconcile against the target's own battery before publishing → pin the revision. Full writeup in METHODOLOGY.md.

## What wants to happen next

Author reruns the packet; their verdict dictates the next iteration. The product grows when the ecosystem pulls it, not when I push.

---

**Tags:** #IETF #EP-AEC #conformance #verification #spec-defects #independent-implementation

---

*All outcomes recorded in the repository's ITERATION-LOG.md (iterations 0–4).*