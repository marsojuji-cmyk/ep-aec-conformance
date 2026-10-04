# EP-AEC Iteration Log

Organic improvement loop: each iteration observes where the product naturally arrives, records outcomes, and lets the next step emerge from what actually happened.

## Iteration Protocol
1. **Observe** — what just happened? (external event, user action, test result)
2. **Iterate** — what's the smallest useful improvement?
3. **Record** — what changed, what we learned, what wants to happen next

---

## Iteration 0 — Foundation (2026-10-03)

**What happened:** 360° audit of the EP-AEC receipt conformance verifier. Product had 54 conformance vectors, 4 adversarial probes, no packaging, no CLI, no methodology doc.

**What we built:**
- Packaging: pyproject.toml, requirements.txt, `pip install .` works
- Shared fixtures: verifier/fixtures.py (single source for keys, helpers)
- pytest integration: 56 native test functions
- CLI: `python -m verifier {verify,probe,vectors}`
- Signature abstraction: verifier/signature.py (SignatureScheme protocol)
- Methodology doc: METHODOLOGY.md (5-step transferable method)
- F1 finding as conformance vector (section I)
- README rewritten for strangers
- Reconciled against EMILIA's EP-CANONICALIZATION-v1 (33/35 → 35/35)
- Submitted issue #864 to emiliaprotocol/emilia-protocol

**Current state:**
- 56/56 pytest pass
- 4/4 adversarial probes reproduce
- 35/35 EP-CANONICALIZATION-v1 pass
- Issue #864 OPEN on emiliaprotocol/emilia-protocol

---

## Iteration 1 — Adversarial Review (2026-10-03)

**What happened:** User asked to "scale through iterations that organically improve" and "record all outcomes on Grok.com." Grok Build was at free tier limit, so Raven did the adversarial review in-lane.

**Review scope:** Edge case testing, JSON parsing robustness, type safety, code quality.

**Findings (ranked by impact):**

### F1: Invalid UTF-8 crashes with UnicodeDecodeError (MEDIUM)
- **Location:** verifier/jcs.py load_ijson()
- **Issue:** `b'{"a":\xff}'` raises UnicodeDecodeError instead of CanonicalizationError
- **Impact:** A malformed JSON input with invalid UTF-8 bytes crashes the parser instead of returning a graceful error
- **Fix:** Catch UnicodeDecodeError in load_ijson and wrap it as CanonicalizationError
- **Severity:** Medium — the verifier catches it at the chain level, but the jcs module itself isn't fail-closed

### F2: No rate limiting or size bounds on requirement expressions (LOW)
- **Location:** verifier/epaec.py RequirementParser
- **Issue:** A requirement with 1000 terms processes without error
- **Impact:** Potential DoS via extremely long requirement strings
- **Fix:** Add a max term count (e.g., 1000) and reject if exceeded
- **Severity:** Low — the 4096 char bound exists, but term count isn't bounded

### F3: Missing test coverage for concurrent verification (LOW)
- **Location:** tests/test_conformance.py
- **Issue:** No tests for thread safety or concurrent chain verification
- **Impact:** Unknown behavior under concurrent load
- **Fix:** Add a test that verifies the same chain from multiple threads
- **Severity:** Low — the verifier is stateless, so concurrent use is likely safe

### F4: No input validation on Policy fields (LOW)
- **Location:** verifier/epaec.py Policy dataclass
- **Issue:** Policy accepts any value for pinned_executor_keys, requirement, etc.
- **Impact:** Invalid policy could cause unexpected behavior
- **Fix:** Add validation in __post_init__ for key format, requirement syntax
- **Severity:** Low — the verifier handles invalid inputs gracefully

### F5: CLI doesn't validate JSON input files (LOW)
- **Location:** verifier/__main__.py cmd_verify()
- **Issue:** If the chain JSON file is malformed, the error message is not user-friendly
- **Impact:** Poor user experience for CLI users
- **Fix:** Add try/except around JSON parsing with clear error message
- **Severity:** Low — the core verifier handles it, but CLI UX could be better

**Edge case test results (all PASS):**
- Empty requirement → DENY ✓
- Whitespace requirement → DENY ✓
- Missing evidence field → DENY ✓
- None type → DENY ✓
- Over max_components → DENY ✓
- Unicode requirement → DENY ✓
- Deep nesting (100) → ALLOW (correctly, since canonicalization catches it) ✓
- Operators only → DENY ✓
- Non-dict chain inputs → DENY ✓
- Non-dict action → DENY ✓
- Non-list components → DENY ✓

---

## Iteration 2 — Fix F1: Invalid UTF-8 crash (2026-10-03)

**What happened:** Found that invalid UTF-8 bytes crash the JSON parser with UnicodeDecodeError instead of CanonicalizationError. This breaks the fail-closed promise.

**What we fixed:** Added UnicodeDecodeError catch in load_ijson() to wrap it as CanonicalizationError.

**Verification:**
- `load_ijson(b'{"a":\xff}')` now raises CanonicalizationError (was UnicodeDecodeError)
- All existing tests still pass (56/56)
- All probes still reproduce (4/4)
- EP-CANONICALIZATION-v1 still passes (35/35)

**Fail-closed verification:**
- Invalid UTF-8: CanonicalizationError → DENY ✓
- Malformed JSON: CanonicalizationError → DENY ✓
- Truncated JSON: CanonicalizationError → DENY ✓
- Binary garbage: CanonicalizationError → DENY ✓

**What wants to happen next:**
1. Wait for EMILIA author's response to issue #864
2. The response dictates iteration 3: if they engage, iterate on their feedback; if silence, iterate on discoverability
3. Grok Build is at free tier limit — retry when limit resets for adversarial review

---

## Recording on Grok.com

**Status:** Grok Build is at free tier limit. Options:
1. **Wait for limit reset** — Grok Build free tier resets periodically
2. **Use SuperGrok** — if Marcus has SuperGrok subscription, higher limits available
3. **Record locally** — all outcomes recorded in ITERATION-LOG.md, can be posted to Grok.com manually
4. **Use alternative** — Codex or Claude Code for adversarial review

**Recommendation:** Record outcomes locally in ITERATION-LOG.md. When Grok Build limit resets, dispatch adversarial review. Post summary to Grok.com when ready.

---

## Iteration 3 — Discoverability & Grok.com (2026-10-03)

**What happened:** User asked to "scale through iterations that organically improve" and "record all outcomes on Grok.com." Grok Build is still at free tier limit.

**What we built:**
- Report generator: scripts/generate_report.py — generates comprehensive status report
- Grok.com post: GROK-POST.md — prepared content for posting to Grok.com
- Updated iteration log with all outcomes

**Current state:**
- 56/56 pytest pass
- 4/4 adversarial probes reproduce
- 35/35 EP-CANONICALIZATION-v1 pass
- Issue #864 OPEN on emiliaprotocol/emilia-protocol
- Fail-closed verified against malformed inputs
- Report generator ready
- Grok.com post prepared

**What wants to happen next:**
1. **Post to Grok.com** — content prepared in GROK-POST.md
2. **Wait for EMILIA author's response** to issue #864
3. **If they engage** → iterate on their feedback
4. **If silence after 7 days** → iterate on discoverability
5. **Retry Grok Build** when limit resets for adversarial review

---

## The Product's Organic Pull

The product is telling us where it wants to go. Right now, it's waiting for external input (the EMILIA author's response). When that arrives, the next iteration will emerge naturally. The product is stable, well-tested, and ready for whatever comes next.

The iteration loop is:
1. **Observe** — what just happened?
2. **Iterate** — what's the smallest useful improvement?
3. **Record** — what changed, what we learned, what wants to happen next

Each iteration is triggered by an external event, not by internal ambition. That's what "organic" means here — the product grows when the ecosystem pulls it, not when we push.

---

## Iteration 4 — The -07 packet (2026-10-03/04)

**What happened:** The ecosystem pulled. The EMILIA author (FutureEnterprises, MEMBER) replied to issue #864: F1 confirmed as a real -02 defect, fixed since -03, labels display-only in -07 §3; P2 reframed as -07 §§6–7 native-commitment MATCH; `a OR b AND c` wanted as a §8 interop regression; asked for source + vectors + one-command runner with revision pinned, and effect/ceremony cases kept separate.

**What we built (Cursor lane parked — `shed_needed:true`, host-hold exception documented):**
- `spec_revision` on `verify_chain` + `Policy` ("02" default, "07" for current draft; unknown revisions raise)
- -07 semantics: labels never enter the satisfied set; chain-only requirement → DENY; `&&`/`||` aliases; IDENT restricted to `1*(ALPHA / DIGIT / "." / ":" / "-" / "_")`
- Section J (J1–J7): -07 vectors — J1 P1 attack now DENYs; J2 chain-only bar DENYs; J3 RP-pinned bar ALLOWs; J4–J6 grammar; J7 unknown revision raises
- Sections F (§8) and G (§9) explicitly marked -02-only (removed from AEC in -03)
- Packet: [gist 30240a10](https://gist.github.com/marsojuji-cmyk/30240a1084cdfc6d033c91827336d420) — `conformance-run-03.json` (63/63), `probe-run-03.json` (4/4, -02 mode), runner doc with one-command repro + -02/-07 table + ask mapping
- Reply posted: [issuecomment-5976831415](https://github.com/emiliaprotocol/emilia-protocol/issues/864#issuecomment-5976831415)

**Verification:**
- `pytest tests/test_conformance.py` → 63/63 (56 -02 untouched + 7 new J)
- `python3 verifier/probe.py` → 4/4 reproduce (probes run default -02, correct)
- EP-CANONICALIZATION-v1 → 35/35 (unchanged)

**What wants to happen next:**
1. Author reruns the packet; their verdict dictates iteration 5
2. If they take B1–B5/P4 as §8 regression vectors → record the adoption
3. If they request the full tree → push it somewhere pullable (their call)
4. Grok.com recording (this iteration's second half)

**Grok.com status: BLOCKED, two independent walls (both verified live this turn).**
- Wall 1: Grok Build CLI free-tier limit still exhausted (`grok -p "Say ok."` → usage-limit error).
- Wall 2: Hermes browser has no usable backend — cloud provider unreachable (Nous gateway not entitled) AND local fallback refused (default browser is not Chromium, even though Google Chrome.app is installed).
- Prepared artifact: `GROK-POST.md` holds the full post content, ready to paste.
- Unblock paths (Marc-only, pick one): (a) set Chrome as default browser — System Settings → Desktop & Dock → Default web browser → Google Chrome — then say "go" and I drive grok.com; (b) SuperGrok subscription lifts the CLI limit; (c) paste `GROK-POST.md` into grok.com by hand (30 seconds).

---

## Scoped GitHub grant (Marc-approved 2026-10-03 ~23:15 MDT)

**Grant:** scoped reign over GitHub as `marsojuji-cmyk` (scopes live-verified: `gist`, `read:org`, `repo`, `workflow`).
**✅ allowed:** issue comments (own threads + EMILIA #864), gist create/update/delete, branch create+push and PR open on own repos (never direct to `main`), repo reads/clones/verify runs.
**❌ denied (ask every time):** repo delete, force-push, visibility flips, settings/secrets/tokens/org actions, any spend.
**Lease:** until the #864 author's verdict lands OR 2026-10-10 23:59 MDT, whichever first — then expires, re-ask.
**Rollback:** every mutation logged here with its URL; gists/branches deletable on Marc's word; issue comments editable via `gh`.
**Falsifier:** any mutation without a receipt URL in this log = violation → grant collapses to ask-everything instantly.

---