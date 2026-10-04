"""
signature.py — pluggable signature scheme abstraction.

EP-AEC §1.1 is explicit: the spec "does NOT define any component receipt format."
The signature scheme is therefore a deployment choice, not a spec constraint.

This module defines a protocol that any signature scheme must satisfy. The
default implementation uses Ed25519 via PyNaCl (the fixture convention used
throughout this project). A deployment that needs RSA, ECDSA-P256, or
post-quantum schemes implements the same protocol.

Usage:
    from signature import Ed25519Scheme, SignatureScheme

    scheme = Ed25519Scheme()
    sig = scheme.sign(payload_bytes, signing_key)
    ok = scheme.verify(payload_bytes, sig, verify_key)
"""

from __future__ import annotations

import base64
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SignatureScheme(Protocol):
    """Protocol for pluggable signature schemes."""

    def sign(self, payload: bytes, key: Any) -> bytes:
        """Sign `payload` with `key`, return raw signature bytes."""
        ...

    def verify(self, payload: bytes, signature: bytes, public_key: Any) -> bool:
        """Verify `signature` over `payload` with `public_key`. Return True iff valid."""
        ...

    def encode_public_key(self, key: Any) -> str:
        """Encode a public key to its transport form (e.g. base64)."""
        ...

    def decode_public_key(self, encoded: str) -> Any:
        """Decode a transport-encoded public key."""
        ...


class Ed25519Scheme:
    """Ed25519 via PyNaCl — the default fixture scheme."""

    def sign(self, payload: bytes, key: Any) -> bytes:
        from nacl.signing import SigningKey
        if isinstance(key, bytes):
            key = SigningKey(key)
        return key.sign(payload).signature

    def verify(self, payload: bytes, signature: bytes, public_key: Any) -> bool:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
        if isinstance(public_key, str):
            public_key = base64.b64decode(public_key)
        if isinstance(public_key, bytes):
            public_key = VerifyKey(public_key)
        try:
            public_key.verify(payload, signature)
            return True
        except (BadSignatureError, ValueError, TypeError):
            return False

    def encode_public_key(self, key: Any) -> str:
        if hasattr(key, 'verify_key'):
            key = bytes(key.verify_key)
        return base64.b64encode(bytes(key)).decode('ascii')

    def decode_public_key(self, encoded: str) -> Any:
        from nacl.signing import VerifyKey
        return VerifyKey(base64.b64decode(encoded))