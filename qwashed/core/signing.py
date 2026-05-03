# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Ed25519 signing primitives for Qwashed.

Scope
-----
This module implements only the *classical* leg of Qwashed's signature
strategy: Ed25519 generation, sign, and verify, plus key
serialization helpers. The hybrid Ed25519||ML-DSA-65 construction lives in
:mod:`qwashed.vault.hybrid_sig` (Phase 3) so that the audit module can
ship before the ML-DSA dependency stack is required.

Audit reports use Ed25519-only signatures by default and gain an optional
ML-DSA-65 second signature when the user opts in via vault-managed keys.

All operations are wrappers over the ``cryptography`` library's primitives.
Qwashed itself rolls no crypto. Every error path raises
:class:`SignatureError`; silent ``return False`` on a verify failure is
permitted only for :func:`verify` itself, which returns a strict ``bool``
to match the standard verify API.

Examples
--------
>>> sk = SigningKey.generate()
>>> vk = sk.verify_key
>>> sig = sk.sign(b"audit-payload")
>>> vk.verify(b"audit-payload", sig)
True
"""

from __future__ import annotations

import base64
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from qwashed.core.errors import SignatureError

__all__ = [
    "ED25519_PUBKEY_LEN",
    "ED25519_SIGNATURE_LEN",
    "SigningKey",
    "VerifyKey",
]

#: Ed25519 public-key length in bytes per RFC 8032.
ED25519_PUBKEY_LEN: Final[int] = 32

#: Ed25519 signature length in bytes per RFC 8032.
ED25519_SIGNATURE_LEN: Final[int] = 64


class VerifyKey:
    """Ed25519 public key.

    Wrap a :class:`cryptography.hazmat...Ed25519PublicKey`. Provides
    :meth:`verify` (returns bool, never raises on signature mismatch),
    plus :meth:`to_bytes` / :meth:`to_b64` / :meth:`from_bytes` /
    :meth:`from_b64` for stable on-disk representation.
    """

    __slots__ = ("_pk",)

    def __init__(self, pk: Ed25519PublicKey) -> None:
        self._pk = pk

    # -- construction --------------------------------------------------------

    @classmethod
    def from_bytes(cls, raw: bytes) -> VerifyKey:
        """Build from the 32-byte raw public key encoding (RFC 8032)."""
        if len(raw) != ED25519_PUBKEY_LEN:
            raise SignatureError(
                f"Ed25519 public key must be {ED25519_PUBKEY_LEN} bytes, got {len(raw)}",
                error_code="signing.bad_pubkey_length",
            )
        try:
            pk = Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:
            raise SignatureError(
                f"failed to parse Ed25519 public key: {exc}",
                error_code="signing.bad_pubkey",
            ) from exc
        return cls(pk)

    @classmethod
    def from_b64(cls, encoded: str) -> VerifyKey:
        """Build from base64 of the raw 32-byte public key."""
        try:
            raw = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise SignatureError(
                f"public key is not valid base64: {exc}",
                error_code="signing.bad_pubkey_b64",
            ) from exc
        return cls.from_bytes(raw)

    # -- serialization -------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Return the raw 32-byte public key (RFC 8032 encoding)."""
        return self._pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def to_b64(self) -> str:
        """Return base64 of the raw 32-byte public key."""
        return base64.b64encode(self.to_bytes()).decode("ascii")

    # -- verify --------------------------------------------------------------

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify ``signature`` over ``message``.

        Returns ``True`` on success, ``False`` on signature mismatch, and
        raises :class:`SignatureError` only for *structural* failures:
        wrong-length signature, malformed key, etc. This matches the
        standard signature-verify API where "bad signature" is a normal
        outcome but "I don't know what this thing is" is an error.
        """
        if len(signature) != ED25519_SIGNATURE_LEN:
            raise SignatureError(
                f"Ed25519 signature must be {ED25519_SIGNATURE_LEN} bytes, got {len(signature)}",
                error_code="signing.bad_signature_length",
            )
        try:
            self._pk.verify(signature, message)
        except InvalidSignature:
            return False
        except Exception as exc:  # pragma: no cover - defensive
            raise SignatureError(
                f"unexpected verify failure: {exc}",
                error_code="signing.verify_failed",
            ) from exc
        return True

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VerifyKey):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash(self.to_bytes())

    def __repr__(self) -> str:
        return f"VerifyKey({self.to_b64()[:8]}...)"


class SigningKey:
    """Ed25519 private key.

    Holds an :class:`Ed25519PrivateKey`. Use :meth:`generate` for a fresh
    keypair, or :meth:`from_bytes` to load a previously-stored 32-byte
    seed. The corresponding public key is exposed via :attr:`verify_key`.

    The raw seed is never logged. ``__repr__`` returns the verify-key
    fingerprint only.
    """

    __slots__ = ("_sk",)

    def __init__(self, sk: Ed25519PrivateKey) -> None:
        self._sk = sk

    # -- construction --------------------------------------------------------

    @classmethod
    def generate(cls) -> SigningKey:
        """Generate a fresh Ed25519 keypair."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_bytes(cls, seed: bytes) -> SigningKey:
        """Build from the 32-byte raw seed (RFC 8032 ``a`` value)."""
        if len(seed) != ED25519_PUBKEY_LEN:
            raise SignatureError(
                f"Ed25519 private seed must be {ED25519_PUBKEY_LEN} bytes, got {len(seed)}",
                error_code="signing.bad_seed_length",
            )
        try:
            sk = Ed25519PrivateKey.from_private_bytes(seed)
        except Exception as exc:
            raise SignatureError(
                f"failed to parse Ed25519 private key: {exc}",
                error_code="signing.bad_seed",
            ) from exc
        return cls(sk)

    # -- serialization -------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Return the raw 32-byte private seed.

        WARNING: this is sensitive material. Never log, never include in
        an error message, never write to a file without going through
        :mod:`qwashed.vault`'s passphrase-encrypted store.
        """
        return self._sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def verify_key(self) -> VerifyKey:
        """Return the public key for this signing key."""
        return VerifyKey(self._sk.public_key())

    # -- sign ---------------------------------------------------------------

    def sign(self, message: bytes) -> bytes:
        """Produce an Ed25519 signature over ``message``.

        Returns the 64-byte signature.
        """
        try:
            return self._sk.sign(message)
        except Exception as exc:  # pragma: no cover - defensive
            raise SignatureError(
                f"Ed25519 sign failed: {exc}",
                error_code="signing.sign_failed",
            ) from exc

    def __repr__(self) -> str:
        return f"SigningKey(verify_key={self.verify_key!r})"
