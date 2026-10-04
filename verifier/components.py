"""
components.py — component verifiers for EP-AEC, including §8 and §9.

THE POINT OF THIS FILE. draft-schrock-ep-authorization-evidence-chain-02 §13
says, in the draft's own words:

    "The evidence rules for the effect-attestation and ceremony-evidence record
     types (Section 8, Section 9) are implemented in a JavaScript-only reference
     evaluation in the same repository; they are not yet part of the shared
     cross-language conformance vector set."

and

    "These are one project's implementations -- a cross-language consistency
     check, not independently developed implementations."

So §8/§9 have (a) no cross-language vectors and (b) no independent
implementation. This file is an independent implementation of those two
sections, and test_conformance.py is the vector set.

SIGNATURE CONSTRUCTION (fixture convention, NOT a spec claim). §1.1 is explicit
that EP-AEC "does NOT define any component receipt format". The signature
transport below is therefore MY fixture convention, stated as such:

    signed payload = RFC 8785 JCS of the evidence object with the
                     "signature" member removed
    signature      = Ed25519 over those bytes, base64

A real deployment substitutes whatever its receipt family specifies. What the
§8/§9 RULES apply to is the *verified* content, and those rules are implemented
here exactly.
"""

from __future__ import annotations

import base64
from typing import Any, Optional

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

try:
    from .epaec import ADMISSIBLE, CONFLICTED, MISSING_EVIDENCE, UNVERIFIABLE, Policy
    from .jcs import CanonicalizationError, canonicalize
except ImportError:
    from epaec import ADMISSIBLE, CONFLICTED, MISSING_EVIDENCE, UNVERIFIABLE, Policy
    from jcs import CanonicalizationError, canonicalize

SIG_FIELD = "signature"


# ==========================================================================
# signing helpers (fixture convention)
# ==========================================================================
def signing_payload(evidence: dict) -> bytes:
    body = {k: v for k, v in evidence.items() if k != SIG_FIELD}
    return canonicalize(body)


def sign_evidence(evidence: dict, signing_key: SigningKey) -> str:
    sig = signing_key.sign(signing_payload(evidence)).signature
    return base64.b64encode(sig).decode("ascii")


def verify_signature(evidence: dict, pubkey_b64: str) -> bool:
    sig_b64 = evidence.get(SIG_FIELD)
    if not isinstance(sig_b64, str):
        return False
    try:
        sig = base64.b64decode(sig_b64, validate=True)
        VerifyKey(base64.b64decode(pubkey_b64)).verify(signing_payload(evidence), sig)
        return True
    except (BadSignatureError, ValueError, TypeError, CanonicalizationError):
        return False


# ==========================================================================
# §2 digest helper
# ==========================================================================
def _norm_digest(s: Any) -> Optional[str]:
    """§8: compare as lowercase hex after removing an optional 'sha256:' prefix."""
    if not isinstance(s, str):
        return None
    return (s[len("sha256:"):] if s.startswith("sha256:") else s).lower()


# ==========================================================================
# §8 — Effect Attestation
# ==========================================================================
def verify_effect_attestation(evidence: dict, policy: Policy) -> dict:
    """
    §8 rules, verbatim:

      * "The record MUST carry the receipt identifier of the authorization it
         attests and the digest of the observed effect, and MUST be signed by
         the executor."
      * "An effect attestation whose executor signature does not verify, or
         whose executor key is not pinned by the relying party, is inadmissible
         as evidence: the component verifier MUST report it invalid, and it MUST
         NOT be weighed as effect evidence at all (fail closed)."
      * "The committed effect digest against which the observed digest is
         compared MUST NOT be taken from the presenter. It is either pinned by
         the relying party ... or read by the component verifier from the
         referenced authorization; where both are available, the relying-party
         pin takes precedence."
      * observed != committed -> "effect_divergence", conflict
      * verified, no observed digest -> "effect_divergence", conflict
      * verified, no committed digest to compare -> "effect_commitment_missing",
        conflict, "never as admissible"
    """
    findings: list[str] = []
    detail: dict = {}

    executor_id = evidence.get("executor")
    if not isinstance(executor_id, str) or not executor_id:
        return {"valid": False, "reason": "missing executor identifier",
                "verdict": UNVERIFIABLE}

    # --- signature + key pinning (fail closed, both conditions) -------------
    pinned = policy.pinned_executor_keys.get(executor_id)
    if pinned is None:
        # §8: key not pinned by the relying party -> INADMISSIBLE.
        return {"valid": False,
                "reason": "executor key not pinned by relying party (inadmissible)",
                "verdict": UNVERIFIABLE,
                "detail": {"executor": executor_id}}

    if not verify_signature(evidence, pinned):
        return {"valid": False,
                "reason": "executor signature does not verify (inadmissible)",
                "verdict": UNVERIFIABLE,
                "detail": {"executor": executor_id}}

    # --- required fields ----------------------------------------------------
    receipt_id = evidence.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        return {"valid": False, "reason": "missing receipt_id", "verdict": UNVERIFIABLE,
                "detail": {"executor": executor_id}}
    detail["receipt_id"] = receipt_id

    action_digest = evidence.get("action_digest")
    if not isinstance(action_digest, str) or not action_digest:
        return {"valid": False, "reason": "missing action_digest",
                "verdict": UNVERIFIABLE, "detail": detail}

    observed = _norm_digest(evidence.get("observed_effect_digest"))
    detail["observed_effect_digest"] = observed

    # --- committed digest: relying-party pin WINS over everything -----------
    committed = _norm_digest(policy.expected_effect_digest)
    committed_source = "relying_party_pin" if committed else None

    if committed is None:
        # §8: read it from the referenced authorization. We only do this from a
        # relying-party-supplied authorization map -- NEVER from the presenter.
        auth_map = getattr(policy, "authorizations", {}) or {}
        ref = auth_map.get(receipt_id)
        if isinstance(ref, dict):
            committed = _norm_digest(ref.get("committed_effect_digest"))
            if committed:
                committed_source = "referenced_authorization"
    detail["committed_effect_digest"] = committed
    detail["committed_source"] = committed_source

    # --- the three conflict rules ------------------------------------------
    verdict = ADMISSIBLE

    if observed is None:
        # verified attestation carrying NO observed digest -> divergence/conflict
        findings.append("effect_divergence: verified attestation carries no observed digest")
        verdict = CONFLICTED
    elif committed is None:
        # cannot tie an observed effect to an approved effect -> NOT admissible
        findings.append(
            "effect_commitment_missing: no committed effect digest to compare against"
        )
        verdict = CONFLICTED
    elif observed != committed:
        findings.append(
            "effect_divergence: observed %s != committed %s" % (observed, committed)
        )
        verdict = CONFLICTED

    return {
        "valid": True,
        "action_digest": action_digest,
        "receipt_id": receipt_id,
        "observed_effect_digest": observed,
        "committed_effect_digest": committed,
        "verdict": verdict,
        "reason": "signature verified; " + (findings[0] if findings else "effect matches commitment"),
        "detail": detail,
        "findings": findings,
    }


# ==========================================================================
# §9 — Ceremony Evidence
# ==========================================================================
def _parse_instant(v: Any) -> Optional[float]:
    """Return seconds since epoch for an RFC 3339-ish timestamp, else None."""
    if not isinstance(v, str) or not v:
        return None
    s = v.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        from datetime import datetime
        return datetime.fromisoformat(s).timestamp()
    except Exception:                                            # noqa: BLE001
        return None


def verify_ceremony_evidence(evidence: dict, policy: Policy) -> dict:
    """
    §9 rules. "The component verifier proves the ceremony record is authentic;
    the rules below judge what it says."

      * floor set; review interval = approved_at - viewed_at, whole seconds
      * interval strictly below floor -> "rubber_stamped_ceremony", conflict
      * telemetry absent/unusable (missing or unparseable viewed_at or
        approved_at, or approved_at earlier than viewed_at) ->
        "ceremony_telemetry_missing", conflict, "never as a silent pass"
      * signature does not verify -> unverifiable, "never softened to a conflict"
      * no floor set -> "this document attaches no judgment to the telemetry"
    """
    findings: list[str] = []
    detail: dict = {}

    approver = evidence.get("approver")
    if not isinstance(approver, str) or not approver:
        return {"valid": False, "reason": "missing approver", "verdict": UNVERIFIABLE}

    signer_id = evidence.get("signer", approver)
    pinned = policy.pinned_executor_keys.get(signer_id)
    if pinned is None:
        return {"valid": False,
                "reason": "ceremony signer key not pinned by relying party",
                "verdict": UNVERIFIABLE, "detail": {"signer": signer_id}}
    if not verify_signature(evidence, pinned):
        # unverifiable -- NEVER softened to a conflict
        return {"valid": False, "reason": "ceremony signature does not verify",
                "verdict": UNVERIFIABLE, "detail": {"signer": signer_id}}

    action_digest = evidence.get("action_digest")
    if not isinstance(action_digest, str) or not action_digest:
        return {"valid": False, "reason": "missing action_digest",
                "verdict": UNVERIFIABLE}

    detail["approver"] = approver
    detail["issued_at"] = evidence.get("issued_at")
    detail["viewed_at"] = evidence.get("viewed_at")
    detail["approved_at"] = evidence.get("approved_at")

    verdict = ADMISSIBLE
    floor = getattr(policy, "ceremony_min_review_sec", None)

    if floor is not None:
        v = _parse_instant(evidence.get("viewed_at"))
        a = _parse_instant(evidence.get("approved_at"))
        if v is None or a is None or a < v:
            findings.append(
                "ceremony_telemetry_missing: viewed_at/approved_at absent, "
                "unparseable, or approved_at earlier than viewed_at"
            )
            verdict = CONFLICTED
        else:
            interval = int(a - v)  # whole seconds
            detail["review_interval_sec"] = interval
            detail["floor_sec"] = floor
            if interval < floor:
                findings.append(
                    "rubber_stamped_ceremony: review interval %ds below floor %ds"
                    % (interval, floor)
                )
                verdict = CONFLICTED

    return {
        "valid": True,
        "action_digest": action_digest,
        "approver": approver,
        "issued_at": evidence.get("issued_at"),
        "viewed_at": evidence.get("viewed_at"),
        "approved_at": evidence.get("approved_at"),
        "verdict": verdict,
        "reason": findings[0] if findings else "ceremony verified, no floor set or interval above floor",
        "detail": detail,
        "findings": findings,
    }


# ==========================================================================
# a plain signed receipt leg -- needed to compose real chains
# ==========================================================================
def verify_signed_receipt(evidence: dict, policy: Policy) -> dict:
    """
    A generic delegation / permit leg. Not a §8/§9 rule; present so chains can be
    composed and so the CROSS-BINDING defense (§4 step 3.3) can be exercised.
    """
    signer = evidence.get("signer")
    if not isinstance(signer, str) or not signer:
        return {"valid": False, "reason": "missing signer", "verdict": UNVERIFIABLE}

    pinned = policy.pinned_executor_keys.get(signer)
    if pinned is None:
        return {"valid": False, "reason": "signer key not pinned by relying party",
                "verdict": UNVERIFIABLE, "detail": {"signer": signer}}
    if not verify_signature(evidence, pinned):
        return {"valid": False, "reason": "signature does not verify",
                "verdict": UNVERIFIABLE, "detail": {"signer": signer}}

    action_digest = evidence.get("action_digest")
    if not isinstance(action_digest, str) or not action_digest:
        return {"valid": False, "reason": "missing action_digest", "verdict": UNVERIFIABLE}

    return {
        "valid": True,
        "action_digest": action_digest,
        "verdict": ADMISSIBLE,
        "reason": "signature verified",
        "detail": {"signer": signer},
    }


def default_registry():
    try:
        from .epaec import ComponentRegistry
    except ImportError:
        from epaec import ComponentRegistry
    r = ComponentRegistry()
    r.register("effect_attestation", verify_effect_attestation)
    r.register("ceremony_evidence", verify_ceremony_evidence)
    r.register("policy-permit", verify_signed_receipt)
    r.register("delegation", verify_signed_receipt)
    return r
