"""
epaec.py — an INDEPENDENT implementation of the EP-AEC verification algorithm.

Implemented from the specification text alone:
  draft-schrock-ep-authorization-evidence-chain-02  (IETF, July 2026)

Sections implemented:
  §2  Canonical action digest  -> SHA-256 over RFC 8785 JCS of the Action Object
  §3  The Authorization Evidence Chain object
  §4  Verification algorithm (fail-closed, 5 steps)
  §5  Requirement expressions (bounded parser, EQUAL precedence, left-to-right)
  §6  Relying-party requirement precedence over the presenter's
  §8  Effect attestation evidence rules
  §9  Ceremony evidence evidence rules

REVISION PINNING. Default behavior implements -02 text (including its
label/type namespace collision, kept so the F1 finding keeps reproducing).
Pass spec_revision="07" (or set Policy.spec_revision="07") for the -07
semantics: labels are display-only and never enter the satisfied set
(-07 §3, fixed since -03); the requirement MUST come from the relying
party (-07 §9 step 3: a chain-only requirement yields UNSATISFIED); the
§8 grammar additionally accepts && / || and restricts IDENT to
1*(ALPHA / DIGIT / "." / ":" / "-" / "_"). Verdicts stay ALLOW/DENY:
-07 permits a legacy allow alias equal to satisfied.

NOT implemented: any component receipt FORMAT. §1.1 is explicit that EP-AEC
"does not define any component receipt format" — component verifiers are
supplied by the relying party, which is what the registry below is for.

Design rule, taken from §4 step 5: "Any unexpected error at any step MUST yield
DENY." Every component verifier is therefore invoked inside a catch-all, and a
raise is a DENY-contributing unsatisfied component — never a crash and never an
optimistic default.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

try:
    from .jcs import CanonicalizationError, canonicalize, load_ijson
except ImportError:
    from jcs import CanonicalizationError, canonicalize, load_ijson

VERSION = "EP-AEC-v1"

#: -07 §8: ident = 1*(ALPHA / DIGIT / "." / ":" / "-" / "_")
_IDENT_RE = re.compile(r'^[A-Za-z0-9.:_-]+$')

# §4: graded verdict set used by the reference evaluation.
ADMISSIBLE = "admissible"
MISSING_EVIDENCE = "missing_evidence"
STALE = "stale"
CONFLICTED = "conflicted"
UNVERIFIABLE = "unverifiable"

#: Verdicts that represent a finding which must never move toward ALLOW (§4).
_CONFLICT_CLASS = {CONFLICTED}

ALLOW = "ALLOW"
DENY = "DENY"


# ==========================================================================
# §2 — canonical action digest
# ==========================================================================
def _strip_sha256_prefix(s: str) -> str:
    """§8: 'Digest values are compared as lowercase hexadecimal after removal
    of an optional "sha256:" prefix.'"""
    if isinstance(s, str) and s.startswith("sha256:"):
        return s[len("sha256:"):].lower()
    return s.lower() if isinstance(s, str) else s


def canonical_action_digest(action: Any, *, prefix: bool = True) -> str:
    """§2: SHA-256 digest of the JCS serialization of the Action Object,
    lowercase hex, optionally prefixed 'sha256:'."""
    raw = canonicalize(action)          # raises CanonicalizationError on non-I-JSON
    hexd = hashlib.sha256(raw).hexdigest()
    return ("sha256:" + hexd) if prefix else hexd


# ==========================================================================
# §5 — requirement expressions
# ==========================================================================
class RequirementSyntaxError(ValueError):
    """Malformed requirement expression. §4 step 5 -> DENY."""


def _tokenize(expr: str) -> list[str]:
    """
    Bounded tokenizer. No regex backtracking, no recursive descent over
    attacker-controlled input beyond the grammar's own depth.

    NOTE (spec ambiguity, reported): §5's grammar gives IDENT as a single
    nonterminal, but §3's example uses labels containing spaces
    ("two-person human authorization"). Whitespace tokenization means such a
    label can never be *referenced* in a requirement expression. Components
    are still matched by their `type`. Recorded as finding F2.
    """
    if not isinstance(expr, str):
        raise RequirementSyntaxError("requirement must be a string")
    if len(expr) > 4096:
        raise RequirementSyntaxError("requirement exceeds bounded length")

    tokens: list[str] = []
    i = 0
    n = len(expr)
    while i < n:
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        if c in "()":
            tokens.append(c)
            i += 1
            continue
        j = i
        while j < n and not expr[j].isspace() and expr[j] not in "()":
            j += 1
        tokens.append(expr[i:j])
        i = j
    return tokens


class RequirementParser:
    """
    §5 grammar (-02):
        expr := term (('AND' | 'OR') term)*
        term := '(' expr ')' | IDENT

    -07 §8 additionally accepts '&&' / '||' as operator aliases and
    restricts IDENT to 1*(ALPHA / DIGIT / "." / ":" / "-" / "_")
    (strict_ident=True).

    "AND and OR have EQUAL binding strength and are evaluated strictly left to
    right; implementations MUST NOT assume AND binds tighter than OR."

    This is the conformance trap: any implementation that hands the expression
    to a language evaluator (Python `eval`, JS `Function`) gets `a AND b OR c`
    wrong, because every mainstream language binds AND tighter. See probe P1.
    """

    #: Operator spellings accepted in each revision.
    _OPS_02 = ("AND", "OR")
    _OPS_07 = ("AND", "OR", "&&", "||")

    def __init__(self, expr: str, *, strict_ident: bool = False):
        self.tokens = _tokenize(expr)
        self.pos = 0
        self.strict_ident = strict_ident
        self.ops = self._OPS_07 if strict_ident else self._OPS_02

    def _peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> Optional[str]:
        t = self._peek()
        if t is not None:
            self.pos += 1
        return t

    def parse(self) -> Callable[[set[str]], bool]:
        node = self._expr()
        if self.pos != len(self.tokens):
            raise RequirementSyntaxError(
                "trailing tokens at position %d: %r" % (self.pos, self.tokens[self.pos:])
            )
        return node

    def _expr(self) -> Callable[[set[str]], bool]:
        left = self._term()
        while True:
            op = self._peek()
            if op not in self.ops:
                break
            self._next()
            right = self._term()
            # left-to-right fold, equal precedence
            if op in ("AND", "&&"):
                l, r = left, right
                left = lambda sat, l=l, r=r: l(sat) and r(sat)   # noqa: E731
            else:
                l, r = left, right
                left = lambda sat, l=l, r=r: l(sat) or r(sat)    # noqa: E731
        return left

    def _term(self) -> Callable[[set[str]], bool]:
        tok = self._next()
        if tok is None:
            raise RequirementSyntaxError("unexpected end of expression")
        if tok == "(":
            node = self._expr()
            if self._next() != ")":
                raise RequirementSyntaxError("unbalanced parenthesis")
            return node
        if tok == ")":
            raise RequirementSyntaxError("unexpected ')'")
        if tok == "":
            raise RequirementSyntaxError("empty identifier")
        if tok in self.ops:
            raise RequirementSyntaxError("unexpected operator %r" % tok)
        if self.strict_ident and not _IDENT_RE.match(tok):
            raise RequirementSyntaxError(
                "identifier %r outside -07 §8 ident charset" % tok
            )
        # §5: "an unknown identifier evaluates to false"
        ident = tok
        return lambda sat, ident=ident: ident in sat


def evaluate_requirement(expr: str, satisfied: set[str], *,
                         strict_ident: bool = False) -> bool:
    parser = RequirementParser(expr, strict_ident=strict_ident)
    return parser.parse()(satisfied)


# ==========================================================================
# §3/§4 — the chain and the algorithm
# ==========================================================================
@dataclass
class ComponentResult:
    index: int
    ctype: str
    label: Optional[str]
    verified: bool = False
    bound: bool = False
    satisfied: bool = False
    reason: str = ""
    verdict: str = MISSING_EVIDENCE
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        d = {
            "index": self.index,
            "type": self.ctype,
            "verified": self.verified,
            "bound": self.bound,
            "satisfied": self.satisfied,
            "reason": self.reason,
            "verdict": self.verdict,
        }
        if self.label is not None:
            d["label"] = self.label
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass
class ChainResult:
    verdict: str
    reason: str
    requirement_source: Optional[str] = None
    chain_digest: Optional[str] = None
    components: list[ComponentResult] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "requirement_source": self.requirement_source,
            "chain_digest": self.chain_digest,
            "components": [c.as_dict() for c in self.components],
            "findings": self.findings,
        }


#: A component verifier takes the `evidence` object and returns a dict with
#: at minimum {"valid": bool, "action_digest": str}. §4 step 3.2.
ComponentVerifier = Callable[[dict, "Policy"], dict]


class ComponentRegistry:
    def __init__(self) -> None:
        self._v: dict[str, ComponentVerifier] = {}

    def register(self, ctype: str, fn: ComponentVerifier) -> None:
        self._v[ctype] = fn

    def get(self, ctype: str) -> Optional[ComponentVerifier]:
        return self._v.get(ctype)


@dataclass
class Policy:
    """
    §6: sufficiency policy supplied OUT-OF-BAND by the relying party.
    §8: the committed effect digest "MUST NOT be taken from the presenter."
    §9: the optional review-latency floor.

    spec_revision selects the draft semantics: "02" (default, implements
    -02 text verbatim including the label/type collision) or "07"
    (labels display-only, requirement must come from the relying party,
    -07 §8 grammar). -02 vectors and probes assume the default.
    """
    requirement: Optional[str] = None            # §6 pinned bar
    expected_effect_digest: Optional[str] = None  # §8 relying-party pin
    pinned_executor_keys: dict[str, Any] = field(default_factory=dict)  # §8
    ceremony_min_review_sec: Optional[int] = None  # §9 review-latency floor
    #: §8: referenced authorizations, supplied by the RELYING PARTY. The
    #: committed digest is read from here at need -- never from the presenter.
    authorizations: dict[str, Any] = field(default_factory=dict)
    #: Draft revision semantics: "02" (default) or "07". See module docstring.
    spec_revision: str = "02"


def _as_text(obj: Any) -> str:
    try:
        try:
            from .jcs import canonicalize_str  # noqa
        except ImportError:
            from jcs import canonicalize_str  # noqa
        return canonicalize_str(obj)
    except Exception:
        return repr(obj)


def verify_chain(
    raw_chain: bytes | str | dict,
    registry: ComponentRegistry,
    policy: Optional[Policy] = None,
    *,
    max_components: int = 256,
    spec_revision: Optional[str] = None,
) -> ChainResult:
    """
    §4 verification algorithm. Fail-closed at every step.

    Steps 1-5 implemented in order; a raise anywhere yields DENY (§4 step 5).

    spec_revision selects the draft semantics ("02" default, "07" for the
    current draft). An explicit argument wins; otherwise Policy.spec_revision
    is used. Unknown revisions raise ValueError — silently accepting an
    unknown revision would be the opposite of fail-closed.
    """
    policy = policy or Policy()
    revision = spec_revision if spec_revision is not None else policy.spec_revision
    if revision not in ("02", "07"):
        raise ValueError("unknown spec_revision %r (want '02' or '07')" % revision)
    is07 = revision == "07"

    # ---- step 1: structural validation -------------------------------------
    try:
        C = load_ijson(raw_chain) if not isinstance(raw_chain, dict) else raw_chain
    except CanonicalizationError as e:
        return ChainResult(DENY, "malformed chain JSON: %s" % e)

    if not isinstance(C, dict):
        return ChainResult(DENY, "malformed: chain is not an object")

    if C.get("@version") != VERSION:
        return ChainResult(DENY, "missing or wrong @version (want %s)" % VERSION)

    action = C.get("action")
    if not isinstance(action, dict):
        return ChainResult(DENY, "missing or non-object 'action'")

    components = C.get("components")
    if not isinstance(components, list) or not components:
        return ChainResult(DENY, "missing or empty 'components'")
    if len(components) > max_components:
        return ChainResult(DENY, "components exceeds bounded count")

    requirement = C.get("requirement")
    if not isinstance(requirement, str) or not requirement.strip():
        return ChainResult(DENY, "missing 'requirement'")

    # ---- step 2: chain digest ----------------------------------------------
    try:
        chain_digest = canonical_action_digest(action, prefix=False)
    except CanonicalizationError as e:
        return ChainResult(DENY, "Action Object outside I-JSON profile: %s" % e)

    declared = C.get("action_digest")
    if declared is not None:
        if _strip_sha256_prefix(declared) != chain_digest:
            return ChainResult(
                DENY, "declared action_digest does not equal recomputed digest"
            )

    # ---- step 3: per-component --------------------------------------------
    results: list[ComponentResult] = []
    satisfied_set: set[str] = set()
    findings: list[str] = []

    for idx, k in enumerate(components):
        if not isinstance(k, dict):
            results.append(ComponentResult(idx, "?", None, reason="component is not an object"))
            continue

        ctype = k.get("type")
        label = k.get("label")
        evidence = k.get("evidence")
        cr = ComponentResult(idx, ctype if isinstance(ctype, str) else "?", label)

        if not isinstance(ctype, str) or not ctype:
            cr.reason = "missing component type"
            results.append(cr)
            continue
        if not isinstance(evidence, dict):
            cr.reason = "missing or non-object evidence"
            results.append(cr)
            continue

        # 3.1 no verifier registered for k.type -> unsatisfied, continue
        fn = registry.get(ctype)
        if fn is None:
            cr.reason = "no verifier"
            results.append(cr)
            continue

        # 3.2 invoke; any exception marks k unsatisfied (§4 step 5)
        try:
            out = fn(evidence, policy)
        except Exception as e:                                   # noqa: BLE001
            cr.reason = "verifier raised: %s: %s" % (type(e).__name__, e)
            cr.verdict = UNVERIFIABLE
            results.append(cr)
            continue

        if not isinstance(out, dict) or "valid" not in out:
            cr.reason = "verifier returned malformed result"
            cr.verdict = UNVERIFIABLE
            results.append(cr)
            continue

        cr.verified = bool(out.get("valid"))
        returned_digest = out.get("action_digest")
        if isinstance(out.get("detail"), dict):
            cr.detail = out["detail"]
        if out.get("verdict"):
            cr.verdict = out["verdict"]
        if out.get("findings"):
            findings.extend(out["findings"])

        # 3.3 satisfied iff valid AND binds the SAME action (cross-binding defense)
        if not cr.verified:
            cr.reason = out.get("reason") or "signature/evidence invalid"
            results.append(cr)
            continue

        if not isinstance(returned_digest, str):
            cr.reason = "verifier returned no action digest"
            cr.verdict = UNVERIFIABLE
            results.append(cr)
            continue

        cr.bound = _strip_sha256_prefix(returned_digest) == chain_digest
        if not cr.bound:
            cr.reason = "binds a different action"
            cr.verdict = CONFLICTED
            results.append(cr)
            continue

        cr.satisfied = True
        cr.reason = "verified and bound"
        if cr.verdict == MISSING_EVIDENCE:
            cr.verdict = ADMISSIBLE
        # 3.4 (-02): satisfied set gets type AND label. -07 §3: labels are
        # display-only and never enter the set.
        satisfied_set.add(ctype)
        if not is07 and isinstance(label, str) and label:
            satisfied_set.add(label)
        results.append(cr)

    # ---- step 4: requirement selection + evaluation ------------------------
    # -02 §6: a relying-party requirement takes precedence over the
    # presenter's. -07 §9 step 3: the chain requirement is descriptive
    # only -- if the only available requirement came from C, UNSATISFIED.
    if policy.requirement is not None:
        effective = policy.requirement
        source = "relying_party"
        if policy.requirement != requirement:
            findings.append(
                "presenter requirement %r ignored in favour of pinned relying-party "
                "bar %r" % (requirement, policy.requirement)
            )
    elif is07:
        return ChainResult(
            DENY,
            "no relying-party requirement: chain requirement is descriptive only",
            requirement_source="presenter",
            chain_digest=chain_digest,
            components=results,
            findings=findings,
        )
    else:
        effective = requirement
        source = "presenter"

    try:
        ok = evaluate_requirement(effective, satisfied_set, strict_ident=is07)
    except RequirementSyntaxError as e:
        return ChainResult(
            DENY,
            "requirement expression invalid: %s" % e,
            requirement_source=source,
            chain_digest=chain_digest,
            components=results,
            findings=findings,
        )

    # §4: conflict-class findings never move the outcome toward ALLOW.
    conflicted = [c for c in results if c.verdict in _CONFLICT_CLASS]
    if ok and conflicted:
        return ChainResult(
            DENY,
            "requirement satisfied but %d component(s) raised conflict-class findings"
            % len(conflicted),
            requirement_source=source,
            chain_digest=chain_digest,
            components=results,
            findings=findings,
        )

    verdict = ALLOW if ok else DENY
    reason = (
        "requirement satisfied" if ok else "requirement not satisfied by the satisfied set"
    )
    return ChainResult(
        verdict,
        reason,
        requirement_source=source,
        chain_digest=chain_digest,
        components=results,
        findings=findings,
    )
