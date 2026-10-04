"""
EP-AEC Conformance Verifier — independent implementation of
draft-schrock-ep-authorization-evidence-chain-02 (IETF, July 2026).

Usage:
    from verifier import verify_chain, Policy, ComponentRegistry
    from verifier.components import default_registry

    result = verify_chain(chain_dict, default_registry(), policy)
    print(result.verdict)  # "ALLOW" or "DENY"
"""

try:
    # When imported as a package (python -m verifier, or from verifier import ...)
    from .epaec import (
        ADMISSIBLE,
        ALLOW,
        CONFLICTED,
        DENY,
        MISSING_EVIDENCE,
        STALE,
        UNVERIFIABLE,
        ChainResult,
        ComponentRegistry,
        ComponentResult,
        Policy,
        canonical_action_digest,
        evaluate_requirement,
        verify_chain,
    )
except ImportError:
    # When sys.path includes verifier/ directly (tests, probe.py)
    from epaec import (
        ADMISSIBLE,
        ALLOW,
        CONFLICTED,
        DENY,
        MISSING_EVIDENCE,
        STALE,
        UNVERIFIABLE,
        ChainResult,
        ComponentRegistry,
        ComponentResult,
        Policy,
        canonical_action_digest,
        evaluate_requirement,
        verify_chain,
    )

__all__ = [
    "ADMISSIBLE",
    "ALLOW",
    "CONFLICTED",
    "DENY",
    "MISSING_EVIDENCE",
    "STALE",
    "UNVERIFIABLE",
    "ChainResult",
    "ComponentRegistry",
    "ComponentResult",
    "Policy",
    "canonical_action_digest",
    "evaluate_requirement",
    "verify_chain",
]