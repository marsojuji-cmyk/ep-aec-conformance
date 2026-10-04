"""
fixtures.py — shared test fixtures for conformance vectors and adversarial probes.

Keys, helpers, and fixture actions used by both test_conformance.py and probe.py.
Ed25519 via PyNaCl; the signature scheme is a fixture convention, not a spec claim.
"""

from __future__ import annotations

import base64
from typing import Any, Optional

from nacl.signing import SigningKey

try:
    from .epaec import Policy, canonical_action_digest
    from .components import sign_evidence
except ImportError:
    from epaec import Policy, canonical_action_digest
    from components import sign_evidence

# ---------------------------------------------------------------------------
# Fixture keys (deterministic, never random — reproducibility over entropy)
# ---------------------------------------------------------------------------
EXEC = SigningKey(bytes(range(32)))           # executor
HUMAN = SigningKey(bytes(range(32, 64)))      # accountable human
AGENT = SigningKey(bytes(range(64, 96)))      # delegating agent
UNPINNED = SigningKey(bytes(range(96, 128)))  # a key the verifier does NOT trust


def pk(k: SigningKey) -> str:
    """Base64-encoded public key (verify key)."""
    return base64.b64encode(bytes(k.verify_key)).decode()


def signed(evidence: dict, key: SigningKey) -> dict:
    """Sign an evidence object (fixture convention: JCS of body, Ed25519)."""
    e = {k: v for k, v in evidence.items() if k != "signature"}
    e["signature"] = sign_evidence(e, key)
    return e


# ---------------------------------------------------------------------------
# Fixture actions and digests
# ---------------------------------------------------------------------------
ACTION = {"actor": "agent-1", "verb": "release", "target": "db/records", "amount": 3}
DIGEST = canonical_action_digest(ACTION, prefix=False)

OTHER_ACTION = {"actor": "agent-1", "verb": "release", "target": "db/records", "amount": 300}
OTHER_DIGEST = canonical_action_digest(OTHER_ACTION, prefix=False)


# ---------------------------------------------------------------------------
# Fixture policies
# ---------------------------------------------------------------------------
POLICY = Policy(pinned_executor_keys={
    "executor-1": pk(EXEC),
    "human-1": pk(HUMAN),
    "agent-1": pk(AGENT),
})


# ---------------------------------------------------------------------------
# Chain/component builders
# ---------------------------------------------------------------------------
def chain(
    components: list,
    action: Any = None,
    requirement: str = "delegation",
    action_digest: Optional[str] = None,
) -> dict:
    """Build an EP-AEC chain object from components."""
    c = {
        "@version": "EP-AEC-v1",
        "action": action if action is not None else ACTION,
        "components": components,
        "requirement": requirement,
    }
    if action_digest is not None:
        c["action_digest"] = action_digest
    return c


def comp(ctype: str, evidence: dict, label: Optional[str] = None) -> dict:
    """Build a component entry."""
    d = {"type": ctype, "evidence": evidence}
    if label:
        d["label"] = label
    return d