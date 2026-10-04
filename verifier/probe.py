#!/usr/bin/env python3
"""
probe.py — adversarial probes against draft-schrock-ep-authorization-evidence-chain-02.

Purpose: the spec is only as strong as its fail-closed claims. This file tries to
BREAK them with a conformant verifier, and reports honestly what held and what did not.

Every probe is written from the specification text, not from anyone's implementation.
Run: python3 verifier/probe.py
"""

from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from epaec import (ALLOW, DENY, Policy, canonical_action_digest,        # noqa: E402
                   evaluate_requirement, verify_chain, ComponentRegistry,
                   RequirementSyntaxError)
from jcs import canonicalize                                             # noqa: E402
from nacl.signing import VerifyKey                                       # noqa: E402
from nacl.exceptions import BadSignatureError                            # noqa: E402
from fixtures import (ACTION, AGENT, DIGEST, EXEC, UNPINNED as ATTACKER, # noqa: E402
                      pk, signed, OTHER_ACTION, OTHER_DIGEST)

REG = __import__("components").default_registry()

FINDINGS: list[dict] = []
def finding(pid, title, attack_succeeded, detail):
    FINDINGS.append({"probe": pid, "title": title,
                     "attack_succeeded": attack_succeeded, "detail": detail})
    verdict = "ATTACK SUCCEEDS -- finding" if attack_succeeded else "defense holds"
    print("\n[%s] %s\n      -> %s\n      %s" % (pid, title, verdict, detail))


print("=" * 74)
print("ADVERSARIAL PROBES — EP-AEC draft-02, independent implementation")
print("=" * 74)

# ==========================================================================
print("\n--- P1: label/type namespace collision in the satisfied set ---")
# §4 step 3.4: "If satisfied, add k.type and k.label (if present) to the satisfied set."
# §5:          "IDENT matches a component type or label in the satisfied set."
# The label is PRESENTER-CONTROLLED. Both live in ONE namespace. So a presenter
# holding a single valid receipt may be able to satisfy a requirement naming a
# type they never supplied -- by labelling their receipt with that type's name.
# ==========================================================================
pinned = Policy(
    pinned_executor_keys={"agent-1": pk(AGENT), "executor-1": pk(EXEC)},
    requirement="delegation AND ep-quorum",   # a human quorum is DEMANDED
)
leg = signed({"signer": "agent-1", "action_digest": DIGEST}, AGENT)

# honest chain: one delegation leg, no human quorum -> must DENY
r_honest = verify_chain({"@version": "EP-AEC-v1", "action": ACTION, "requirement": "delegation",
                         "components": [{"type": "delegation", "evidence": leg}]}, REG, pinned)

# attack chain: SAME single leg, but labelled with the demanded type name
r_attack = verify_chain({"@version": "EP-AEC-v1", "action": ACTION, "requirement": "delegation",
                         "components": [{"type": "delegation", "label": "ep-quorum",
                                         "evidence": leg}]}, REG, pinned)

print("      honest chain (1 delegation leg, no quorum) : %s" % r_honest.verdict)
print("      attacker chain (same leg, label='ep-quorum'): %s" % r_attack.verdict)
finding("P1", "Presenter-controlled label satisfies a required component TYPE",
        r_attack.verdict == ALLOW and r_honest.verdict == DENY,
        "Requirement 'delegation AND ep-quorum' has NO human leg in the attacker "
        "chain; the only difference is a label string. VERDICT: honest=%s attacker=%s. "
        "Cause: §4 step 3.4 puts type and label into one satisfied set, and §5 "
        "resolves IDENT against both." % (r_honest.verdict, r_attack.verdict))

# ==========================================================================
print("\n--- P2: cross-binding defense depends on component formats signing the action ---")
# §1.1: "EP-AEC does NOT define any component receipt format."
# §4 step 3.3 compares the digest the VERIFIER returns against chain_digest.
# If a component format's signature does not cover its action binding, an attacker
# rewrites the binding in transit. EP-AEC cannot detect this -- it is out of scope.
# ==========================================================================

def loose_verifier(evidence, policy):
    """A component verifier whose format signs a body that EXCLUDES action_digest."""
    signer = evidence.get("signer")
    pin = policy.pinned_executor_keys.get(signer)
    if pin is None:
        return {"valid": False, "reason": "key not pinned"}
    body = {k: v for k, v in evidence.items() if k not in ("signature", "action_digest")}
    try:
        VerifyKey(base64.b64decode(pin)).verify(
            canonicalize(body), base64.b64decode(evidence["signature"]))
    except (BadSignatureError, Exception):
        return {"valid": False, "reason": "bad signature"}
    return {"valid": True, "action_digest": evidence.get("action_digest")}


LOOSE = ComponentRegistry()
LOOSE.register("delegation", loose_verifier)

# NOTE: P2 needs its OWN policy. Inheriting P1's pinned bar
# ("delegation AND ep-quorum") makes both chains DENY for an unrelated reason --
# the probe would report "defense holds" while measuring nothing. Caught by
# re-reading the result instead of trusting the verdict.
P2POLICY = Policy(pinned_executor_keys={"agent-1": pk(AGENT), "executor-1": pk(EXEC)},
                  requirement="delegation")

# A receipt format that signs its body but NOT its action binding.
# The SAME signature is then presentable as authorizing two DIFFERENT actions.
SMALL = {"actor": "agent-1", "verb": "release", "target": "db/records", "amount": 3}
BIG = {"actor": "agent-1", "verb": "release", "target": "db/records", "amount": 3_000_000}
SMALL_DIGEST = canonical_action_digest(SMALL, prefix=False)
BIG_DIGEST = canonical_action_digest(BIG, prefix=False)

# the receipt body as actually issued -- note action_digest is NOT in it
body = {"signer": "agent-1", "receipt_id": "rcpt-small"}
sig = base64.b64encode(AGENT.sign(canonicalize(body)).signature).decode()

presented_small = dict(body, action_digest=SMALL_DIGEST, signature=sig)
presented_big = dict(body, action_digest=BIG_DIGEST, signature=sig)   # rewritten in transit

r_small = verify_chain({"@version": "EP-AEC-v1", "action": SMALL, "requirement": "delegation",
                        "components": [{"type": "delegation", "evidence": presented_small}]},
                       LOOSE, P2POLICY)
r_big = verify_chain({"@version": "EP-AEC-v1", "action": BIG, "requirement": "delegation",
                      "components": [{"type": "delegation", "evidence": presented_big}]},
                     LOOSE, P2POLICY)
print("      ONE signature, small action (3 units)      : %s" % r_small.verdict)
print("      ONE signature, BIG action (3,000,000 units): %s" % r_big.verdict)
finding("P2", "Cross-binding defense is only as strong as each component's signature coverage",
        r_small.verdict == ALLOW and r_big.verdict == ALLOW,
        "A component format that omits the action binding from its signed body "
        "lets ONE valid signature authorize TWO different actions -- both chains "
        "return ALLOW. EP-AEC's core defense (§4 step 3.3) is therefore "
        "conditional on a property the spec explicitly declines to define "
        "(§1.1). Architectural boundary, not an implementation bug -- but "
        "'EP-AEC conformant' alone does NOT imply cross-binding safety, and the "
        "draft should say so in Security Considerations.")

# ==========================================================================
print("\n--- P3: §5 IDENT cannot express labels containing spaces ---")
# §3's own example labels a component "two-person human authorization".
# §5's grammar makes IDENT a single token and §5 tokenises on whitespace.
# Therefore no requirement expression can reference that label.
# ==========================================================================
try:
    evaluate_requirement("two-person human authorization", {"two-person human authorization"})
    p3_detail = "parsed without error"
    p3_ok = False
except RequirementSyntaxError as e:
    p3_detail = "RequirementSyntaxError: %s" % e
    p3_ok = True
print("      requirement %r -> %s" % ("two-person human authorization", p3_detail))
finding("P3", "§3's own example label is unreferenceable by §5's grammar",
        p3_ok,
        "§3 shows label=\"two-person human authorization\". §5's grammar defines "
        "IDENT as one token and the expression tokenises on whitespace, so that "
        "label can never appear in a requirement. Labels are usable only if they "
        "contain no spaces. Spec inconsistency; fix is to quote or escape IDENT.")

# ==========================================================================
print("\n--- P4: the left-to-right precedence trap ---")
# §5: "implementations MUST NOT assume AND binds tighter than OR."
# Demonstrate that the obvious implementation is non-conformant.
# ==========================================================================
expr = "a OR b AND c"
sat = {"a"}
conformant = evaluate_requirement(expr, sat)
# the naive implementation everyone writes first: hand it to the language evaluator
def naive(expr, sat):
    toks = []
    for t in expr.split():
        if t == "AND":
            toks.append("and")
        elif t == "OR":
            toks.append("or")
        elif t in "()":
            toks.append(t)
        else:
            toks.append(str(t in sat))
    return bool(eval(" ".join(toks)))          # noqa: S307
naive_result = naive(expr, sat)
print("      %r over %s  conformant(LTR)=%s   naive(precedence)=%s" % (expr, sat, conformant, naive_result))
finding("P4", "Conformant left-to-right evaluation diverges from conventional precedence",
        conformant != naive_result,
        "Same expression, same satisfied set, opposite verdicts. This is a "
        "deliberate spec choice, and it is the single most likely "
        "interoperability failure for independent implementations. Recommend "
        "the draft publish this exact vector.")

# ==========================================================================
# summary
# ==========================================================================
print("\n" + "=" * 74)
attacks = [f for f in FINDINGS if f["attack_succeeded"]]
print("PROBE SUMMARY — %d probe(s), %d finding(s)" % (len(FINDINGS), len(attacks)))
for f in FINDINGS:
    print("  %-4s %-8s %s" % (f["probe"], "FINDING" if f["attack_succeeded"] else "held", f["title"]))
print("=" * 74)

if "--json" in sys.argv:
    out = sys.argv[sys.argv.index("--json") + 1]
    json.dump({"spec": "draft-schrock-ep-authorization-evidence-chain-02",
               "implementation": "darpa-seat/independent-python",
               "probes": FINDINGS}, open(out, "w"), indent=2)
    print("wrote", out)