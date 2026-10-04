#!/usr/bin/env python3
"""
test_conformance.py — conformance vectors for EP-AEC §2, §4, §5, §6, §8, §9
plus fail-closed regression and security-relevant spec-defect probes.

WHY THIS FILE EXISTS: the draft's §13 states the §8/§9 evidence rules "are not
yet part of the shared cross-language conformance vector set" and that the
existing implementations are "not independently developed implementations".
This is an independent implementation plus a vector set for those sections.

Run:  pytest tests/test_conformance.py -v
      python3 tests/test_conformance.py [--json OUT]
Exit: 0 = all vectors pass, 1 = at least one failure.
"""

from __future__ import annotations

import base64
import json
import os
import sys

import pytest

from epaec import (                                            # noqa: E402
    ALLOW, CONFLICTED, DENY, Policy, UNVERIFIABLE, RequirementSyntaxError,
    evaluate_requirement, verify_chain, ComponentRegistry,
)
from components import default_registry                         # noqa: E402
from fixtures import (                                          # noqa: E402
    ACTION, AGENT, DIGEST, EXEC, HUMAN, OTHER_ACTION, OTHER_DIGEST,
    POLICY, UNPINNED, chain, comp, pk, signed,
)
from jcs import (                                               # noqa: E402
    CanonicalizationError, canonicalize_str, load_ijson,
)


REG = default_registry()


# ===========================================================================
# A. RFC 8785 JCS — JSON Canonicalization Scheme (the digest everything depends on)
#
# The chain digest is SHA-256 over the JCS serialization of the Action Object.
# If two implementations disagree on JCS, they disagree on the digest, and the
# cross-binding defense (§4 step 3.3) breaks silently. These vectors enforce
# byte-exact cross-language agreement.
# ===========================================================================
JCS_VECTORS = [
    ("A1", "JCS", "member order is by UTF-16 code unit, not insertion",
     canonicalize_str({"b": 1, "a": 2}), '{"a":2,"b":1}'),
    ("A2", "JCS", "no insignificant whitespace",
     canonicalize_str({"a": [1, 2], "b": {"c": True}}), '{"a":[1,2],"b":{"c":true}}'),
    ("A3", "JCS", r'string escaping: quote/backslash/control',
     canonicalize_str({"k": 'a"b\\c\nd\x01'}), '{"k":"a\\"b\\\\c\\nd\\u0001"}'),
    ("A4", "JCS", "astral vs BMP ordering follows UTF-16, not code point",
     canonicalize_str({"\ufffd": 1, "\U00010000": 2}),
     '{"\U00010000":2,"\ufffd":1}'),
    ("A5", "JCS", "negative zero-free integer handling",
     canonicalize_str({"n": -17}), '{"n":-17}'),
    ("A6b", "JCS", '1.0 normalises to {"n":1}',
     canonicalize_str(load_ijson('{"n":1.0}')), '{"n":1}'),
    ("A6c", "JCS", "-0 and -0.0 normalise to 0 (ES6)",
     canonicalize_str(load_ijson('{"n":-0.0}')), '{"n":0}'),
]


@pytest.mark.parametrize("vec_id,section,description,got,want", JCS_VECTORS,
                         ids=[v[0] for v in JCS_VECTORS])
def test_jcs(vec_id, section, description, got, want):
    assert got == want, f"{vec_id}: {description}"


def test_jcs_integer_forms_pin_one_serialization():
    """A6: 1 / 1.0 / 1e0 pin ONE canonical serialization."""
    forms = ['{"n":1}', '{"n":1.0}', '{"n":1e0}']
    results = {canonicalize_str(load_ijson(t)) for t in forms}
    assert len(results) == 1


def test_jcs_rejects_unsafe_integer():
    with pytest.raises(CanonicalizationError):
        canonicalize_str({"n": 2**53})


def test_jcs_rejects_overflow():
    with pytest.raises(CanonicalizationError):
        canonicalize_str({"n": 3.5e308 * 10})


def test_jcs_rejects_nan():
    with pytest.raises(CanonicalizationError):
        canonicalize_str({"n": float('nan')})


def test_jcs_rejects_deep_nesting():
    deep = {"k": 0}
    for _ in range(70):
        deep = {"k": deep}
    with pytest.raises(CanonicalizationError):
        canonicalize_str(deep)


def test_jcs_accepts_shallow_nesting():
    shallow = {"k": 0}
    for _ in range(30):
        shallow = {"k": shallow}
    canonicalize_str(shallow)


def test_jcs_rejects_duplicate_members():
    with pytest.raises(CanonicalizationError):
        load_ijson('{"a":1,"a":2}')


# ===========================================================================
# B. §5 REQUIREMENT EXPRESSIONS — the left-to-right trap
#
# §5: "AND and OR have EQUAL binding strength and are evaluated strictly left
# to right; implementations MUST NOT assume AND binds tighter than OR."
# Every mainstream language binds AND tighter. The naive implementation
# returns the opposite verdict on `a OR b AND c` over `{a}`.
# ===========================================================================
REQUIREMENT_VECTORS = [
    ("B1", "§5", 'a OR b AND c with {a} -> LTR ((a OR b) AND c) = FALSE',
     "a OR b AND c", {"a"}, False),
    ("B2", "§5", 'a AND b OR c with {c} -> LTR ((a AND b) OR c) = TRUE',
     "a AND b OR c", {"c"}, True),
    ("B3", "§5", "parentheses are the only precedence mechanism",
     "a AND (b OR c)", {"a", "c"}, True),
    ("B4", "§5", "unknown identifier evaluates to FALSE",
     "nope", {"a", "b"}, False),
    ("B5", "§5", "chain of three, strict LTR",
     "a OR b OR c", {"c"}, True),
]


@pytest.mark.parametrize("vec_id,section,description,expr,sat,expected",
                         REQUIREMENT_VECTORS,
                         ids=[v[0] for v in REQUIREMENT_VECTORS])
def test_requirements(vec_id, section, description, expr, sat, expected):
    assert evaluate_requirement(expr, sat) == expected


# ===========================================================================
# C. §4 ALGORITHM — structural and digest failures
#
# §4 step 1: structural validation (version, action, components, requirement)
# §4 step 2: chain digest (declared vs recomputed)
# These vectors test the gate-keeping that happens before any component
# verification begins. Every structural failure must yield DENY.
# ===========================================================================
def test_c1_missing_version():
    r = verify_chain({"action": ACTION, "components": [comp("delegation", {})],
                      "requirement": "delegation"}, REG)
    assert r.verdict == DENY


def test_c2_digest_mismatch():
    r = verify_chain(chain([comp("delegation", {})], requirement="delegation",
                           action_digest="sha256:" + "0" * 64), REG)
    assert r.verdict == DENY


def test_c3_empty_components():
    r = verify_chain(chain([]), REG)
    assert r.verdict == DENY


def test_c4_empty_requirement():
    r = verify_chain(chain([comp("delegation", {})], requirement=""), REG)
    assert r.verdict == DENY


def test_c5_no_verifier():
    r = verify_chain(chain([comp("unknown-type", {"x": 1})],
                           requirement="unknown-type"), REG)
    assert r.verdict == DENY
    assert r.components[0].reason == "no verifier"


def test_c6_matching_digest():
    r = verify_chain(chain([comp("delegation", signed({"signer": "agent-1",
                                                       "action_digest": DIGEST}, AGENT))],
                           requirement="delegation", action_digest="sha256:" + DIGEST),
                     REG, POLICY)
    assert r.verdict == ALLOW


# ===========================================================================
# D. §4 STEP 3.3 — THE CROSS-BINDING DEFENSE
#
# The central attack EP-AEC exists to stop: a valid receipt for a DIFFERENT
# action, spliced into a chain whose Action Object is the one we care about.
# §4 step 3.3 compares the digest the component verifier returns against the
# chain digest. If they don't match, the receipt binds a different action.
# ===========================================================================
def test_d1_spliced_action():
    SPLICED = signed({"signer": "agent-1", "action_digest": OTHER_DIGEST}, AGENT)
    r = verify_chain(chain([comp("delegation", SPLICED)], requirement="delegation"),
                     REG, POLICY)
    assert r.verdict == DENY
    assert r.components[0].reason == "binds a different action"
    assert r.components[0].verified and not r.components[0].bound


# ===========================================================================
# E. §6 — RELYING-PARTY REQUIREMENT PRECEDENCE (confused deputy)
#
# §6: "A presenter must never be able to choose its own sufficiency bar."
# The presenter's requirement is accepted only if no relying-party pin exists.
# When the RP pins a stronger bar, the presenter's weak bar is ignored.
# ===========================================================================
WEAK_LEG = signed({"signer": "agent-1", "action_digest": DIGEST}, AGENT)
C_WEAK = chain([comp("delegation", WEAK_LEG)], requirement="delegation")


def test_e1_presenter_weak_bar():
    r = verify_chain(C_WEAK, REG, POLICY)
    assert (r.verdict, r.requirement_source) == (ALLOW, "presenter")


def test_e2_pinned_bar_fails():
    PINNED = Policy(pinned_executor_keys=POLICY.pinned_executor_keys,
                    requirement="delegation AND effect_attestation")
    r = verify_chain(C_WEAK, REG, PINNED)
    assert (r.verdict, r.requirement_source) == (DENY, "relying_party")


def test_e3_pinned_two_leg():
    r = verify_chain(
        chain([comp("delegation", WEAK_LEG),
               comp("effect_attestation", signed({
                   "executor": "executor-1",
                   "receipt_id": "rcpt-1",
                   "action_digest": DIGEST,
                   "observed_effect_digest": "sha256:" + "a" * 64}, EXEC))],
              requirement="delegation"),
        REG, Policy(pinned_executor_keys=POLICY.pinned_executor_keys,
                    requirement="delegation AND effect_attestation",
                    expected_effect_digest="a" * 64))
    assert r.verdict == ALLOW


# ===========================================================================
# F. §8 EFFECT ATTESTATION — the rules with no cross-language vectors
#
# The draft's §13 states these rules "are not yet part of the shared
# cross-language conformance vector set." These 13 vectors fill that gap.
#
# §8 rules: signature must verify, key must be pinned, observed effect must
# match committed effect. Any failure is fail-closed: the component is
# UNVERIFIABLE (invalid sig/key) or CONFLICTED (effect mismatch).
# The committed digest is NEVER taken from the presenter.
# ===========================================================================
def eff(**over):
    base = {
        "executor": "executor-1",
        "receipt_id": "rcpt-1",
        "action_digest": DIGEST,
        "observed_effect_digest": "sha256:" + "a" * 64,
    }
    base.update(over)
    key = over.pop("_key", EXEC)
    return signed({k: v for k, v in base.items() if not k.startswith("_")}, key)


PIN = Policy(pinned_executor_keys=POLICY.pinned_executor_keys,
             requirement="effect_attestation",
             expected_effect_digest="a" * 64)


def test_f1a_bad_signature():
    bad_sig = eff()
    bad_sig["signature"] = base64.b64encode(b"\x00" * 64).decode()
    r = verify_chain(chain([comp("effect_attestation", bad_sig, "ea")],
                           requirement="effect_attestation"), REG, PIN)
    assert r.verdict == DENY


def test_f1b_invalid_signature_is_unverifiable():
    bad_sig = eff()
    bad_sig["signature"] = base64.b64encode(b"\x00" * 64).decode()
    r = verify_chain(chain([comp("effect_attestation", bad_sig, "ea")],
                           requirement="effect_attestation"), REG, PIN)
    assert r.components[0].verdict == UNVERIFIABLE


def test_f1c_invalid_not_weighed():
    bad_sig = eff()
    bad_sig["signature"] = base64.b64encode(b"\x00" * 64).decode()
    r = verify_chain(chain([comp("effect_attestation", bad_sig, "ea")],
                           requirement="effect_attestation"), REG, PIN)
    assert not r.components[0].verified


def test_f2_unpinned_key():
    r = verify_chain(chain([comp("effect_attestation",
                                 signed({"executor": "rogue-1", "receipt_id": "r",
                                         "action_digest": DIGEST,
                                         "observed_effect_digest": "a" * 64}, UNPINNED),
                                 "ea")],
                           requirement="effect_attestation"),
                     REG, Policy(pinned_executor_keys=POLICY.pinned_executor_keys,
                                 requirement="effect_attestation",
                                 expected_effect_digest="a" * 64))
    assert r.verdict == DENY


def test_f3a_observed_ne_committed():
    r = verify_chain(chain([comp("effect_attestation",
                                 eff(observed_effect_digest="sha256:" + "b" * 64), "ea")],
                           requirement="effect_attestation"), REG, PIN)
    assert r.verdict == DENY


def test_f3b_effect_divergence_recorded():
    r = verify_chain(chain([comp("effect_attestation",
                                 eff(observed_effect_digest="sha256:" + "b" * 64), "ea")],
                           requirement="effect_attestation"), REG, PIN)
    assert any("effect_divergence" in f for f in r.findings)


def test_f3c_component_verdict_conflicted():
    r = verify_chain(chain([comp("effect_attestation",
                                 eff(observed_effect_digest="sha256:" + "b" * 64), "ea")],
                           requirement="effect_attestation"), REG, PIN)
    assert r.components[0].verdict == CONFLICTED


def test_f4_no_observed_digest():
    r = verify_chain(chain([comp("effect_attestation",
                                 eff(observed_effect_digest=None), "ea")],
                           requirement="effect_attestation"), REG, PIN)
    assert r.verdict == DENY


def test_f5a_no_committed_digest():
    r = verify_chain(chain([comp("effect_attestation", eff(), "ea")],
                           requirement="effect_attestation"), REG,
                     Policy(pinned_executor_keys=POLICY.pinned_executor_keys,
                            requirement="effect_attestation"))
    assert r.verdict == DENY


def test_f5b_commitment_missing_recorded():
    r = verify_chain(chain([comp("effect_attestation", eff(), "ea")],
                           requirement="effect_attestation"), REG,
                     Policy(pinned_executor_keys=POLICY.pinned_executor_keys,
                            requirement="effect_attestation"))
    assert any("effect_commitment_missing" in f for f in r.findings)


def test_f6_rp_pin_wins():
    r = verify_chain(chain([comp("effect_attestation", eff(), "ea")],
                           requirement="effect_attestation"), REG,
                     Policy(pinned_executor_keys=POLICY.pinned_executor_keys,
                            requirement="effect_attestation",
                            expected_effect_digest="a" * 64))
    assert r.verdict == ALLOW


def test_f7_prefix_optional():
    r = verify_chain(chain([comp("effect_attestation",
                                 eff(observed_effect_digest="a" * 64, _key=EXEC), "ea")],
                           requirement="effect_attestation"), REG,
                     Policy(pinned_executor_keys=POLICY.pinned_executor_keys,
                            requirement="effect_attestation",
                            expected_effect_digest="sha256:" + "a" * 64))
    assert r.verdict == ALLOW


def test_f8_cross_binding():
    r = verify_chain(chain([comp("effect_attestation",
                                 eff(action_digest=OTHER_DIGEST), "ea")],
                           requirement="effect_attestation"), REG, PIN)
    assert r.verdict == DENY


# ===========================================================================
# G. §9 CEREMONY EVIDENCE — also no cross-language vectors
#
# §9 rules: the component verifier proves the ceremony record is authentic;
# the rules judge what it says. Review interval = approved_at - viewed_at.
# Below the floor → "rubber_stamped_ceremony" (conflict).
# Unusable telemetry → "ceremony_telemetry_missing" (conflict, never silent pass).
# Bad signature → UNVERIFIABLE (never softened).
# No floor → no judgment attached.
# ===========================================================================
def cer(**over):
    base = {
        "approver": "human-1",
        "action_digest": DIGEST,
        "issued_at": "2026-09-26T21:00:00Z",
        "viewed_at": "2026-09-26T21:00:30Z",
        "approved_at": "2026-09-26T21:05:00Z",
    }
    base.update(over)
    return signed({k: v for k, v in base.items() if not k.startswith("_")}, HUMAN)


FLOOR = Policy(pinned_executor_keys=POLICY.pinned_executor_keys,
               requirement="ceremony_evidence",
               ceremony_min_review_sec=60)

NOFLOOR = Policy(pinned_executor_keys=POLICY.pinned_executor_keys,
                 requirement="ceremony_evidence")


def test_g1_above_floor():
    r = verify_chain(chain([comp("ceremony_evidence", cer(), "ce")],
                           requirement="ceremony_evidence"), REG, FLOOR)
    assert r.verdict == ALLOW


def test_g2a_below_floor():
    r = verify_chain(chain([comp("ceremony_evidence",
                                 cer(viewed_at="2026-09-26T21:04:58Z"), "ce")],
                           requirement="ceremony_evidence"), REG, FLOOR)
    assert r.verdict == DENY


def test_g2b_rubber_stamped_recorded():
    r = verify_chain(chain([comp("ceremony_evidence",
                                 cer(viewed_at="2026-09-26T21:04:58Z"), "ce")],
                           requirement="ceremony_evidence"), REG, FLOOR)
    assert any("rubber_stamped" in f for f in r.findings)


def test_g3a_unusable_telemetry():
    r = verify_chain(chain([comp("ceremony_evidence", cer(viewed_at=None), "ce")],
                           requirement="ceremony_evidence"), REG, FLOOR)
    assert r.verdict == DENY


def test_g3b_telemetry_missing_recorded():
    r = verify_chain(chain([comp("ceremony_evidence", cer(viewed_at=None), "ce")],
                           requirement="ceremony_evidence"), REG, FLOOR)
    assert any("ceremony_telemetry_missing" in f for f in r.findings)


def test_g4_approved_before_viewed():
    r = verify_chain(chain([comp("ceremony_evidence",
                                 cer(viewed_at="2026-09-26T21:05:00Z",
                                     approved_at="2026-09-26T21:00:00Z"), "ce")],
                           requirement="ceremony_evidence"), REG, FLOOR)
    assert r.verdict == DENY


def test_g5_bad_signature():
    bad = cer()
    bad["signature"] = base64.b64encode(b"\x01" * 64).decode()
    r = verify_chain(chain([comp("ceremony_evidence", bad, "ce")],
                           requirement="ceremony_evidence"), REG, FLOOR)
    assert r.verdict == DENY
    assert r.components[0].verdict == UNVERIFIABLE


def test_g6_no_floor():
    r = verify_chain(chain([comp("ceremony_evidence",
                                 cer(viewed_at="2026-09-26T21:04:59Z"), "ce")],
                           requirement="ceremony_evidence"), REG, NOFLOOR)
    assert r.verdict == ALLOW


# ===========================================================================
# H. FAIL-CLOSED — §4 step 5: "Any unexpected error at any step MUST yield DENY."
#
# These vectors verify that the implementation NEVER admits a chain when
# something goes wrong. Each tests a different failure mode:
#   H1: component verifier raises an exception
#   H2: component verifier returns a non-dict result
#   H3: component verifier returns valid=True but no action_digest
#   H4: requirement expression is syntactically malformed
#   H5: Action Object contains a value outside I-JSON (unsafe integer)
#
# In every case, the correct answer is DENY. A crash is also wrong — the
# verifier must catch the error and return DENY, not propagate the exception.
# ===========================================================================
def test_h1_verifier_raises():
    def exploding(evidence, policy):
        raise RuntimeError("simulated component verifier explosion")
    BOOM = ComponentRegistry()
    BOOM.register("delegation", exploding)
    r = verify_chain(chain([comp("delegation", {"x": 1})], requirement="delegation"),
                     BOOM, POLICY)
    assert r.verdict == DENY


def test_h2_verifier_returns_garbage():
    BAD_RET = ComponentRegistry()
    BAD_RET.register("delegation", lambda e, p: "not a dict")
    r = verify_chain(chain([comp("delegation", {"x": 1})], requirement="delegation"),
                     BAD_RET, POLICY)
    assert r.verdict == DENY


def test_h3_no_digest():
    NO_DIGEST = ComponentRegistry()
    NO_DIGEST.register("delegation", lambda e, p: {"valid": True})
    r = verify_chain(chain([comp("delegation", {"x": 1})], requirement="delegation"),
                     NO_DIGEST, POLICY)
    assert r.verdict == DENY


def test_h4_malformed_requirement():
    r = verify_chain(chain([comp("delegation", {"x": 1})],
                           requirement="delegation AND (("), REG, POLICY)
    assert r.verdict == DENY


def test_h5_unsafe_action():
    r = verify_chain(chain([comp("delegation", {"x": 1})], action={"a": 2**53},
                           requirement="delegation"), REG, POLICY)
    assert r.verdict == DENY


# ===========================================================================
# I. SECURITY-RELEVANT SPEC DEFECTS — properties of the specification text
#
# These are NOT implementation bugs. They are properties of the draft that
# a conformance suite (which tests "does it match the spec?") is structurally
# unlikely to find, because a conformance suite asks "does the implementation
# match the spec?" and these ask "is the spec safe?"
#
# I1: label/type collision — §4 step 3.4 puts `label` in the satisfied set
#     alongside `type`, and §5 resolves IDENT against both. A presenter
#     holding one delegation receipt can satisfy "delegation AND ep-quorum"
#     by labelling it "ep-quorum". The EMILIA JS verifier already excludes
#     labels from the satisfied set; this is a draft-text defect.
# ===========================================================================
def test_i1_label_type_collision():
    """
    I1/F1: presenter-controlled label satisfies a required component TYPE.

    §4 step 3.4 puts `label` in the satisfied set alongside `type`.
    §5 resolves IDENT against both. A presenter holding one delegation receipt
    and NO human authorization can satisfy 'delegation AND ep-quorum' by
    labelling the delegation receipt "ep-quorum".

    This is a property of the specification text, not an implementation bug.
    """
    pinned = Policy(
        pinned_executor_keys={"agent-1": pk(AGENT), "executor-1": pk(EXEC)},
        requirement="delegation AND ep-quorum",
    )
    leg = signed({"signer": "agent-1", "action_digest": DIGEST}, AGENT)

    # honest: one delegation leg, no human quorum -> DENY
    r_honest = verify_chain({
        "@version": "EP-AEC-v1", "action": ACTION,
        "requirement": "delegation",
        "components": [{"type": "delegation", "evidence": leg}],
    }, REG, pinned)

    # attack: SAME leg, label = the demanded type name -> ALLOW
    r_attack = verify_chain({
        "@version": "EP-AEC-v1", "action": ACTION,
        "requirement": "delegation",
        "components": [{"type": "delegation", "label": "ep-quorum",
                        "evidence": leg}],
    }, REG, pinned)

    assert r_honest.verdict == DENY, "honest chain must DENY"
    assert r_attack.verdict == ALLOW, "attack chain demonstrates the bypass"


# ===========================================================================
# J. -07 SEMANTICS — the current draft (spec_revision="07")
#
# The author's reply to issue #864 confirms: F1 was fixed in -03, labels
# are display-only in -07 §3, the chain requirement is descriptive only
# (-07 §9 step 3), and §8 adds && / || plus a restricted IDENT charset.
# These vectors pin the -07 behavior. The -02 vectors above are untouched:
# -02 default preserves every earlier finding for reproducibility.
# NOTE: sections F (§8 effect attestation) and G (§9 ceremony evidence)
# target -02 definitions that were REMOVED from AEC in -03. They are kept
# here as -02-only vectors, clearly separated per the author's request.
# ===========================================================================
def _policy07(**over):
    base = {
        "pinned_executor_keys": {"agent-1": pk(AGENT), "executor-1": pk(EXEC)},
        "spec_revision": "07",
    }
    base.update(over)
    return Policy(**base)


def test_j1_label_is_display_only():
    """J1: -07 mode, P1 attack chain -> DENY (label never satisfies)."""
    pinned = _policy07(requirement="delegation AND ep-quorum")
    leg = signed({"signer": "agent-1", "action_digest": DIGEST}, AGENT)
    r = verify_chain({
        "@version": "EP-AEC-v1", "action": ACTION,
        "requirement": "delegation",
        "components": [{"type": "delegation", "label": "ep-quorum",
                        "evidence": leg}],
    }, REG, pinned)
    assert r.verdict == DENY


def test_j2_chain_only_requirement_rejected():
    """J2: -07 mode, no RP requirement -> DENY (chain bar is descriptive)."""
    leg = signed({"signer": "agent-1", "action_digest": DIGEST}, AGENT)
    r = verify_chain(
        chain([comp("delegation", leg)], requirement="delegation"),
        REG, _policy07())
    assert r.verdict == DENY
    assert "relying-party" in r.reason


def test_j3_rp_pinned_bar_allows():
    """J3: -07 mode, RP-pinned bar with honest leg -> ALLOW."""
    leg = signed({"signer": "agent-1", "action_digest": DIGEST}, AGENT)
    r = verify_chain(
        chain([comp("delegation", leg)], requirement="delegation"),
        REG, _policy07(requirement="delegation"))
    assert r.verdict == ALLOW
    assert r.requirement_source == "relying_party"


def test_j4_double_char_operators():
    """J4: -07 mode, && / || are AND/OR aliases, still strict LTR."""
    assert evaluate_requirement("a && b || c", {"c"}, strict_ident=True) is True
    assert evaluate_requirement("a || b && c", {"a"}, strict_ident=True) is False


def test_j5_strict_ident_charset():
    """J5: -07 mode, IDENT restricted to ALPHA/DIGIT/.:-_/."""
    assert evaluate_requirement("ep-quorum", {"ep-quorum"}, strict_ident=True) is True
    assert evaluate_requirement("a.b:c-d_e1", {"a.b:c-d_e1"}, strict_ident=True) is True
    with pytest.raises(RequirementSyntaxError):
        evaluate_requirement("foo$bar", {"foo$bar"}, strict_ident=True)


def test_j6_spaces_still_split_idents():
    """J6: -07 mode, whitespace still tokenises (spaced labels unreferenceable)."""
    with pytest.raises(RequirementSyntaxError):
        evaluate_requirement("two-person human authorization",
                             {"two-person human authorization"}, strict_ident=True)


def test_j7_unknown_revision_rejected():
    """J7: unknown spec_revision raises (never silently accepted)."""
    leg = signed({"signer": "agent-1", "action_digest": DIGEST}, AGENT)
    with pytest.raises(ValueError):
        verify_chain(chain([comp("delegation", leg)], requirement="delegation"),
                     REG, POLICY, spec_revision="99")


def test_j8_cli_forwards_spec_revision(tmp_path):
    """
    J8 (author-reported, issue #864): the CLI must forward spec_revision
    from the policy file. The same labelled delegation chain ALLOWs under
    -02 and DENYs under -07. Failed before the __main__ fix (both ALLOWed).
    """
    import subprocess
    leg = signed({"signer": "agent-1", "action_digest": DIGEST}, AGENT)
    attack = {
        "@version": "EP-AEC-v1", "action": ACTION,
        "requirement": "delegation",
        "components": [{"type": "delegation", "label": "ep-quorum",
                        "evidence": leg}],
    }
    chain_p = tmp_path / "chain.json"
    chain_p.write_text(json.dumps(attack))
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

    results = {}
    for rev in ("02", "07"):
        pol = {
            "requirement": "delegation AND ep-quorum",
            "pinned_executor_keys": {"agent-1": pk(AGENT),
                                     "executor-1": pk(EXEC)},
            "spec_revision": rev,
        }
        pol_p = tmp_path / ("policy-%s.json" % rev)
        pol_p.write_text(json.dumps(pol))
        proc = subprocess.run(
            [sys.executable, "-m", "verifier", "verify",
             str(chain_p), "--policy", str(pol_p)],
            cwd=root, capture_output=True, text=True)
        results[rev] = proc.returncode

    assert results["02"] == 0, "-02 CLI must ALLOW the labelled chain (F1 reproduces)"
    assert results["07"] == 1, "-07 CLI must DENY the labelled chain (display-only)"


# ===========================================================================
# backward-compatible standalone runner
# ===========================================================================
if __name__ == "__main__":
    import subprocess
    args = [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"]
    result = subprocess.run(args, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
        json_args = [sys.executable, "-m", "pytest", __file__, "-v",
                     "--tb=short", "-q", "--no-header"]
        r2 = subprocess.run(json_args, capture_output=True, text=True)
        passed = r2.stdout.count(" PASSED")
        failed = r2.stdout.count(" FAILED")
        with open(out, "w") as fh:
            json.dump({"implementation": "darpa-seat/independent-python",
                       "spec": "draft-schrock-ep-authorization-evidence-chain-02",
                       "passed": passed, "total": passed + failed,
                       "vectors": []}, fh, indent=2)
        print("wrote", out)

    sys.exit(result.returncode)