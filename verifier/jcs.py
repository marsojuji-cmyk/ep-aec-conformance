"""
jcs.py — RFC 8785 JSON Canonicalization Scheme, restricted to the I-JSON subset.

EP-AEC §2 requires the Action Object to conform to I-JSON (RFC 7493): strings,
booleans, null, arrays, objects, and SAFE INTEGERS only — "so that the digest is
byte-identical across implementations."

That restriction is what makes this tractable and exact.  The hard part of full
JCS is ECMAScript Number::toString shortest-round-trip formatting for floats;
I-JSON excludes floats from the Action Object entirely.  This module therefore:

  * serializes the I-JSON subset EXACTLY per RFC 8785, and
  * FAILS CLOSED (raises CanonicalizationError) on anything outside it, rather
    than silently emitting a digest that another implementation would disagree
    with.

A wrong digest is worse than no digest: it would make a valid chain read as
cross-bound and a forged one read as bound. Fail-closed is the only safe option.
"""

from __future__ import annotations
import math
import json
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1
MIN_SAFE_INTEGER = -(2**53 - 1)


class CanonicalizationError(ValueError):
    """Raised when input is outside the I-JSON profile. Always fail-closed."""


# --------------------------------------------------------------------------
# RFC 8785 §3.2.2.2 — string serialization (ES6 JSON.stringify escaping rules)
# --------------------------------------------------------------------------
_ESCAPES = {
    '"': '\\"',
    '\\': '\\\\',
    '\b': '\\b',
    '\f': '\\f',
    '\n': '\\n',
    '\r': '\\r',
    '\t': '\\t',
}


def _escape_string(s: str) -> str:
    out = []
    for ch in s:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            # control characters: \u00xx, LOWERCASE hex
            out.append('\\u%04x' % ord(ch))
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def _check_unicode(s: str) -> None:
    """RFC 7493: I-JSON strings must not contain lone surrogates."""
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise CanonicalizationError(
                "I-JSON forbids lone surrogate U+%04X in string" % ord(ch)
            )


def _utf16_sort_key(s: str) -> bytes:
    """
    RFC 8785 §3.2.3 — object members are sorted by their *UTF-16 code unit*
    sequence, compared as unsigned 16-bit values.

    Python sorts str by Unicode code point, which DIVERGES from UTF-16 order for
    characters above U+FFFF (astral plane): e.g. U+FFFD < U+10000 by code point,
    but as UTF-16 U+10000 is the surrogate pair D800 DC00, and D800 < FFFD, so
    UTF-16 order reverses them.  Encoding to UTF-16-BE and comparing bytes gives
    the spec's order exactly.
    """
    return s.encode('utf-16-be')


def _es6_number(x: float) -> str:
    """
    RFC 8785 §3.2.2.3 — number serialization per ECMAScript Number::toString.

    REVISED. An earlier revision of this module REFUSED all floats as outside
    the I-JSON profile. That was wrong against the target's published surface:
    EMILIA's EP-CANONICALIZATION-v1 battery requires that the integer-valued
    tokens `1`, `1.0`, `1e0` and `-0` all pin ONE canonical serialization, i.e.
    they must be ACCEPTED and normalised, not rejected. Rejecting them is
    fail-closed (it cannot admit a forgery) but it is an interoperability
    failure and it is not conformance.

    Coverage: integral values, -0, and Python's shortest-round-trip repr
    normalised to the ES6 exponent shape (`e+21` / `e-7`, no trailing `.0`).
    Non-finite values raise.
    """
    if x != x or x in (float('inf'), float('-inf')):
        raise CanonicalizationError("NaN/Infinity are not I-JSON numbers")
    if x == 0:
        return "0"                                    # -0.0 -> "0" per ES6
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))                            # 1.0 / 1e0 -> "1"
    r = repr(x)                                       # shortest round-trip
    if 'e' in r or 'E' in r:
        mant, _, exp = r.lower().partition('e')
        e = int(exp)
        if mant.endswith('.0'):
            mant = mant[:-2]
        return "%se%s%d" % (mant, '+' if e >= 0 else '-', abs(e))
    return r


#: EMILIA EP-CANONICALIZATION-v1 pins a nesting bound of 64.
MAX_DEPTH = 64


def _serialize(value: Any, out: list, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalizationError(
            "nesting exceeds the suite-pinned bound of %d" % MAX_DEPTH
        )
    if value is None:
        out.append('null')
        return

    if value is True:
        out.append('true')
        return
    if value is False:
        out.append('false')
        return

    # bool is a subclass of int in Python — the two checks above must precede this
    if isinstance(value, int):
        if not (MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER):
            raise CanonicalizationError(
                "integer %d outside I-JSON safe range (+/-2^53-1)" % value
            )
        out.append(str(value))
        return

    if isinstance(value, float):
        if value != value or value in (float('inf'), float('-inf')):
            raise CanonicalizationError("NaN/Infinity are not I-JSON numbers")
        if value != int(value):
            raise CanonicalizationError(
                "non-integer real %r is outside the EP I-JSON profile" % value
            )
        if not (MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER):
            raise CanonicalizationError(
                "float %r outside I-JSON safe integer range (+/-2^53-1)" % value
            )
        out.append(_es6_number(value))
        return

    if isinstance(value, str):
        _check_unicode(value)
        out.append(_escape_string(value))
        return

    if isinstance(value, (list, tuple)):
        out.append('[')
        for i, item in enumerate(value):
            if i:
                out.append(',')
            _serialize(item, out, depth + 1)
        out.append(']')
        return

    if isinstance(value, dict):
        for k in value.keys():
            if not isinstance(k, str):
                raise CanonicalizationError(
                    "object member name must be a string, got %r" % type(k).__name__
                )
            _check_unicode(k)

        out.append('{')
        for i, k in enumerate(sorted(value.keys(), key=_utf16_sort_key)):
            if i:
                out.append(',')
            out.append(_escape_string(k))
            out.append(':')
            _serialize(value[k], out, depth + 1)
        out.append('}')
        return

    raise CanonicalizationError(
        "type %r is outside the I-JSON profile" % type(value).__name__
    )


def canonicalize(value: Any) -> bytes:
    """RFC 8785 canonical serialization of an I-JSON value, as UTF-8 bytes."""
    out: list = []
    _serialize(value, out)
    return ''.join(out).encode('utf-8')


def canonicalize_str(value: Any) -> str:
    return canonicalize(value).decode('utf-8')


def load_ijson(raw: bytes | str) -> Any:
    """
    Parse JSON with the strictness EP-AEC needs:
      * duplicate member names are REJECTED (RFC 8785 assumes a parsed data model
        with unique names; silently keeping the last one is a forgery primitive —
        an attacker can present a chain that two implementations digest
        differently).
      * NaN / Infinity rejected (I-JSON).
    """
    def _pairs(pairs):
        seen = set()
        for k, _ in pairs:
            if k in seen:
                raise CanonicalizationError("duplicate member name %r" % k)
            seen.add(k)
        return dict(pairs)

    def _const(name):
        raise CanonicalizationError("non-I-JSON constant %r" % name)

    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_const)
    except json.JSONDecodeError as e:
        raise CanonicalizationError("malformed JSON: %s" % e) from e
    except UnicodeDecodeError as e:
        raise CanonicalizationError("invalid UTF-8 in JSON: %s" % e) from e
