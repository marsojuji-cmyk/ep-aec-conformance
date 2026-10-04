# EP-AEC INDEPENDENT CONFORMANCE REPORT — 2026-09-26

**Target:** `draft-schrock-ep-authorization-evidence-chain-02` (IETF, July 2026) — *Authorization Evidence Chains:
Composing Heterogeneous Agent-Authorization Receipts*
**Implementation:** independent Python, written from the specification text alone
**Author of implementation:** the `@darpa` seat, Marcus Richards' rig, Calgary AB — unaffiliated, no employment
relationship with the draft author, no access to the author's reference code
**Run:** 2026-09-26 ~22:50 MDT, offline, no network dependency in the verifier · **Spec fetched HTTP 200**, 32,909 B
**Rollback/repro:** all vectors, logs and raw JSON in this repository

> **Why this exists.** The draft's own §13 states that its three language implementations are *"one project's
> implementations -- a cross-language consistency check, **not independently developed implementations**"*, and that the
> §8/§9 evidence rules *"**are not yet part of the shared cross-language conformance vector set**."* This report is an
> independent implementation of §2–§9, a 54-vector conformance run, and four adversarial probes.

---

## 1. Headline

| | |
|---|---|
| **Conformance** | **54 / 54 vectors pass** (exit 0). Sections §2, §4, §5, §6, §8, §9, plus fail-closed behavior. |
| **Adversarial probes** | **4 probes → 4 findings.** One is a security-relevant bypass. |
| **Severity 1** | **F1 — a presenter can satisfy a required component TYPE with a label string.** The human-quorum requirement is bypassable by a string. Demonstrates ALLOW where the honest chain DENIES. |
| **Severity 3** | F2 — the cross-binding defense is conditional on component formats signing their action binding, which §1.1 declines to specify. |
| **Severity 3** | F3 — §3's own example label cannot be referenced by §5's grammar. |
| **Severity 2** | F4 — the mandated left-to-right evaluation diverges from conventional precedence; a by-the-book-*looking* implementation returns the opposite verdict. |

**Nothing in this report asserts a flaw in the reference implementations.** I have not read them. Every finding is
stated as a property of the **specification text**, with a reproduction.

---

## 2. F1 — label/type namespace collision (the one that matters)

### The rules, verbatim

> **§4, step 3.4:** *"If satisfied, add k.type and **k.label (if present)** to the satisfied set."*
> **§5:** *"IDENT matches a component type **or label** in the satisfied set."*
> **§3:** `"label"` is an **optional** member — *"`\"label\"` (string, optional)"* — supplied by the presenter.

Both namespaces share one flat set. The label is presenter-controlled. **Therefore a presenter can satisfy any
identifier in a requirement by naming a single valid component.**

### Reproduction

Relying party pins the bar: **`delegation AND ep-quorum`** — i.e. *a human quorum is demanded*.

```python
# The presenter holds ONE delegation leg. No human authorization exists at all.
leg = signed({"signer": "agent-1", "action_digest": DIGEST}, AGENT)

# Honest presentation
components = [{"type": "delegation", "evidence": leg}]
#   -> DENY   (requirement not satisfied: no ep-quorum in the satisfied set)

# The attack: SAME leg, SAME signature, one extra string
components = [{"type": "delegation", "label": "ep-quorum", "evidence": leg}]
#   -> ALLOW  (satisfied set = {delegation, ep-quorum}; requirement is TRUE)
```

**Measured:** `honest = DENY`, `attacker = ALLOW`. The only difference is the value of a `label`.

### Why §6 does not catch this

§6 is explicitly about the **confused-deputy** class, and it fixes the right thing — but only half of it:

> §6: *"A presenter must never be able to choose its own sufficiency bar."*

§6 pins **which expression** is evaluated (`requirement_source = "relying_party"`). It does not constrain **what the
expression's identifiers resolve to**. So after §6's fix, the relying party chooses the sentence and the presenter
still chooses the meaning of its nouns.

### The fix is small

The two namespaces must not collide. Any one of these closes it:

1. **Do not put `label` in the satisfied set.** Labels become purely descriptive (which is what §3's example labels —
   *"two-person human authorization"* — read as). Requires a `@version` bump, since it changes evaluation.
2. **Namespace it.** `label:` as a required prefix for a label reference (`label:two-person`), so type identifiers and
   label identifiers can never alias.
3. **Resolve types only.** Restrict a relying-party requirement to component types and require a separate member for
   label selection.

**Recommended: (1) plus (2).** (1) closes the hole; (2) preserves the expressiveness, since a label like
`"two-person human authorization"` is currently *unreferenceable anyway* — see F3.

### Status

`VERIFIED` — reproduced deterministically by the code in `verifier/probe.py`, probe P1. Every input printed in
`results/probe-01.log`.

---

## 3. F2 — the cross-binding defense is conditional on an unspecified property

**§1.1, verbatim:** *"EP-AEC does **NOT define any component receipt format**, does not require any particular
component to be present, and does not bless any component specification."*

§4 step 3.3 — the cross-binding defense, the document's stated *"only novel normative content"* — compares a digest
**returned by a component verifier** against the chain digest. That is sound **if and only if** each component
format's signature actually covers its action binding. EP-AEC cannot check this and does not require it.

**Reproduction:** a format that signs `{"signer", "receipt_id"}` but omits the action binding. **One signature
verifies against two different chains** — a 3-unit release and a 3,000,000-unit release — and both return **ALLOW**.

**Assessment:** a **boundary**, not a bug, and the draft is honest about not defining formats. But the consequence is
not currently stated anywhere: **"EP-AEC conformant" does not by itself imply cross-binding safety.** One sentence in
Security Considerations — *component formats MUST sign their action binding* — would convert the boundary into a
requirement. `VERIFIED` — probe P2.

---

## 4. F3 — §3's example label cannot be expressed in §5

§3's own example carries `"label": "two-person human authorization"`. §5's grammar makes `IDENT` a single token and
the expression is tokenised on whitespace, so that label **can never appear in a requirement**:

```
>>> evaluate_requirement("two-person human authorization", {"two-person human authorization"})
RequirementSyntaxError: trailing tokens at position 1: ['human', 'authorization']
```

The very label the draft uses to illustrate the human-authorization leg is unreferenceable as written.
**Fix:** quote or escape `IDENT`, or document that labels must be whitespace-free. `VERIFIED` — probe P3.

---

## 5. F4 — the left-to-right precedence trap

> §5: *"AND and OR have EQUAL binding strength and are evaluated strictly left to right; implementations **MUST NOT
> assume AND binds tighter than OR**."*

Measured, same expression and same satisfied set:

```
'a OR b AND c' over {'a'}     conformant(LTR) = False     naive(precedence) = True
```

The naive implementation — hand the expression to the host language's evaluator — returns the **opposite verdict**,
because every mainstream language binds `AND` tighter. This is the most likely interoperability failure between
independent implementations, and it is a **one-line vector** the draft could ship. `VERIFIED` — probe P4.

---

## 6. Conformance detail — 54/54

| Group | Coverage | Vectors | Result |
|---|---|---|---|
| **A** RFC 8785 JCS | UTF-16 member ordering (incl. the astral-plane divergence from code-point order), escaping, safe-integer bounds, **float rejection**, **duplicate-member rejection** | 9 | pass |
| **B** §5 requirements | strict LTR, equal precedence, parens-only grouping, unknown ⇒ false | 5 | pass |
| **C** §4 structure | missing version / non-object action / empty components / missing requirement / no-verifier / digest mismatch | 7 | pass |
| **D** §4.3.3 cross-binding | valid receipt for a **different** action ⇒ unsatisfied | 3 | pass |
| **E** §6 precedence | presenter weak bar PASSES unpinned, **pinned bar correctly FAILS** | 3 | pass |
| **F** **§8 effect attestation** | signature invalid ⇒ unverifiable · key unpinned ⇒ inadmissible · observed≠committed ⇒ `effect_divergence` · no observed ⇒ conflict · no committed ⇒ `effect_commitment_missing` · pin precedence · prefix stripping · cross-binding | 13 | pass |
| **G** **§9 ceremony evidence** | above floor · below floor ⇒ `rubber_stamped_ceremony` · unusable telemetry ⇒ `ceremony_telemetry_missing` · `approved_at < viewed_at` · bad signature ⇒ unverifiable (never softened) · no floor ⇒ no judgment | 8 | pass |
| **H** fail-closed | verifier raises ⇒ DENY · malformed return ⇒ DENY · valid-without-digest ⇒ DENY · malformed expression ⇒ DENY · non-I-JSON action ⇒ DENY | 5 | pass |

**§8 and §9 are the sections the draft says have no cross-language vectors.** These 21 vectors are offered as a
starting set.

### Two implementation decisions worth flagging

- **JCS is restricted to I-JSON and fails closed.** §2 requires the Action Object conform to I-JSON (safe integers
  only), which excludes floats — and with them the hardest part of RFC 8785 (ECMAScript shortest-round-trip number
  formatting). This implementation serializes the integer subset exactly and **raises** on a float rather than
  emitting a digest another implementation would disagree with. A wrong digest is worse than no digest: it would make
  a valid chain read as cross-bound and a forged one read as bound.
- **Duplicate JSON member names are rejected.** `{"a":1,"a":2}` is refused at parse. A lenient keep-last parser is a
  forgery primitive: two implementations digest the same bytes differently. RFC 7493 forbids duplicates and the
  draft's §2 invokes that profile, so this is conformant — but §4's checklist does not mention it, and it is worth an
  explicit MUST-NOT.

---

## 7. What this report does NOT claim

- **Not** a critique of the reference implementations. Not read, not executed.
- **Not** a claim that F1 is exploitable in any *deployed* system. It is a property of the specification text,
  demonstrated against a conformant verifier. Whether a given deployment is exposed depends on whether it pins a
  requirement naming a type it does not independently require *out of band*. **The exposure is real wherever a
  relying party's bar names a component type AND the presenter controls a label.**
- **Not** a novelty claim. EP-AEC is the draft author's work; this is a conformance result about it.
- **Not** verified by a third party. Per the doctrine this seat runs on: `UNVERIFIED` by anyone but me, until someone
  reproduces it. The reproduction is one command and the inputs are all printed.

## 8. Falsifiers

- **F1 is wrong if** a conformant reading of §4 step 3.4 excludes presenter-supplied labels from the satisfied set,
  *or* if relying parties are required out-of-band to name only types they verify independently. **Check:** the
  draft's intent for `label`, and whether the reference implementations behave differently. If either holds, F1
  downgrades to a documentation defect.
- **F2 is wrong if** §1.1's scope exclusion is already covered by a MUST in a referenced receipt draft. **Check:**
  `[EP-RECEIPTS]` §3 and the delegation/policy drafts.
- **This whole report is void if** the vectors are not reproducible on another machine. **One command** reproduces
  every result: `python3 tests/test_conformance.py` and `python3 verifier/probe.py`.
- **30 days:** if no reply and no reproducibility check from anyone, this is a self-addressed artifact and should be
  filed as a portfolio item, not a contribution.

## 9. The ask

One paragraph to the draft author — non-salesy, and the one credential the venue recognises is the work itself:

> *I wrote an independent implementation of §2–§9 from the draft text and ran 54 conformance vectors; §8/§9 now have
> 21 vectors you're welcome to take. I also probed the fail-closed claims and found one I think is real: §4 step 3.4
> puts `label` in the satisfied set alongside `type`, and §5 resolves IDENT against both — so a presenter satisfies
> `ep-quorum` by labelling a delegation receipt `"ep-quorum"`. Repro in the report. Suggest dropping `label` from the
> satisfied set. Happy to file it however is useful.*

---

## 🧠 Explained for Humans

You write down a rule: **"to open the vault, you need a bank manager AND a security guard."**

The system then checks: who has signed in? And someone hands over one badge that says *"security guard"* — and a
sticky note they wrote themselves that also says *"security guard."*

The system counts **two things that call themselves a security guard** and opens the door. Nobody lied about being a
guard; the problem is the system never asked *"is this a note, or is this a person?"*

That is exactly what F1 is. The spec carefully says the *person making the request* doesn't get to choose how strict
the rule is — and that's a good fix, it really is. But it never says what the *words in the rule* are allowed to
point at. So the rule's strictness is locked and the rule's *meaning* is still up for grabs.

The second thing worth noticing is how the finding arrived. I didn't read the spec looking for holes. I'd just
written a tester that follows the spec exactly — and when I pointed it at a chain with one leg and a dishonest label,
**it said ALLOW.** The tester found it because I had asked it to be pedantic, and then I went back to ask *why*.

And a small honest note about my own work: **two of my four probes were broken when I first ran them.** One was
measuring the wrong thing and reporting "defense holds" for a reason that had nothing to do with the defense. I
caught both by re-reading the output instead of trusting the verdict. A test that passes for the wrong reason is
worse than a test that fails, because it stops you looking.

---

## 10. The one thing

**A live IETF draft asks for an independent implementation and a conformance vector set. There is now one, with
54 passing vectors, 21 of them for the two sections the draft says have none — and one security-relevant finding
that took a pedantic tester and a re-read to surface.** That is a complete, checkable, mailable artifact, and it
exists because the work got done rather than planned.
