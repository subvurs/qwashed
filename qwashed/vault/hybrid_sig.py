# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Hybrid Ed25519 || ML-DSA-65 signature.

Construction
------------
Each hybrid signature is the concatenation of two independent signatures
over the *same* message:

* ``sig_ed25519``  -- 64 bytes, RFC 8032 Ed25519.
* ``sig_mldsa65``  -- 3309 bytes, NIST FIPS 204 ML-DSA-65.

Wire format::

    sig = u32_be(len(sig_ed25519)) || sig_ed25519
       || u32_be(len(sig_mldsa65)) || sig_mldsa65

Verification is **AND-verify**: both component signatures must verify or
the hybrid signature is rejected. There is no "fall back to classical
verify if PQ is unavailable" behavior; the missing PQ component fails
closed.

Public-key envelope is the same length-prefixed shape::

    pk = u32_be(len(pk_ed25519)) || pk_ed25519
       || u32_be(len(pk_mldsa65)) || pk_mldsa65

This module deliberately mirrors :mod:`qwashed.vault.hybrid_kem`'s style
so the two halves of the hybrid posture stay symmetric and reviewable.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from qwashed.core.errors import ConfigurationError, SignatureError
from qwashed.core.signing import (
    ED25519_PUBKEY_LEN,
    ED25519_SIGNATURE_LEN,
    SigningKey,
    VerifyKey,
)

__all__ = [
    "ED25519_PUBKEY_LEN",
    "ED25519_SIGNATURE_LEN",
    "MLDSA65_PUBKEY_LEN",
    "MLDSA65_SECRETKEY_LEN",
    "MLDSA65_SIGNATURE_LEN",
    "HybridSigKeypair",
    "generate_keypair",
    "parse_public_key",
    "serialize_public_key",
    "sign",
    "verify",
]

#: ML-DSA-65 public key length per NIST FIPS 204.
MLDSA65_PUBKEY_LEN: Final[int] = 1952

#: ML-DSA-65 secret key length per NIST FIPS 204.
MLDSA65_SECRETKEY_LEN: Final[int] = 4032

#: ML-DSA-65 signature length per NIST FIPS 204.
MLDSA65_SIGNATURE_LEN: Final[int] = 3309

_MAX_COMPONENT_LEN: Final[int] = 1 << 20  # 1 MiB; far above any FIPS sizes.


def _import_oqs() -> object:
    """Import liboqs lazily and surface a fail-closed configuration error."""
    try:
        import oqs
    except ImportError as exc:  # pragma: no cover - exercised by CI without extras
        raise ConfigurationError(
            "liboqs-python is required for ML-DSA-65; install qwashed[vault]",
            error_code="vault.sig.missing_oqs",
        ) from exc
    return oqs


@dataclass(frozen=True)
class HybridSigKeypair:
    """A hybrid Ed25519 || ML-DSA-65 keypair.

    Both component secrets must be present together. Exposing only the
    classical half is a contract violation: a hybrid identity is no
    longer hybrid if the PQ private key is dropped on the floor.
    """

    ed25519_sk: bytes
    mldsa65_sk: bytes
    ed25519_pk: bytes
    mldsa65_pk: bytes

    def public_bytes(self) -> bytes:
        """Return the serialized hybrid public key envelope."""
        return serialize_public_key(self.ed25519_pk, self.mldsa65_pk)


# ---------------------------------------------------------------------------
# Envelope helpers (mirror hybrid_kem; kept separate so the two modules
# don't import each other's private helpers).
# ---------------------------------------------------------------------------


def _pack(component: bytes) -> bytes:
    if len(component) > _MAX_COMPONENT_LEN:
        raise SignatureError(
            f"hybrid sig component too large: {len(component)} bytes",
            error_code="vault.sig.component_too_large",
        )
    return struct.pack(">I", len(component)) + component


def _unpack(buffer: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(buffer):
        raise SignatureError(
            "hybrid sig envelope truncated at length prefix",
            error_code="vault.sig.truncated_length",
        )
    (length,) = struct.unpack(">I", buffer[offset : offset + 4])
    if length > _MAX_COMPONENT_LEN:
        raise SignatureError(
            f"hybrid sig envelope length out of range: {length}",
            error_code="vault.sig.bad_length",
        )
    start = offset + 4
    end = start + length
    if end > len(buffer):
        raise SignatureError(
            "hybrid sig envelope truncated at component body",
            error_code="vault.sig.truncated_body",
        )
    return buffer[start:end], end


def serialize_public_key(ed25519_pk: bytes, mldsa65_pk: bytes) -> bytes:
    """Serialize the hybrid public key into the canonical wire format."""
    if len(ed25519_pk) != ED25519_PUBKEY_LEN:
        raise SignatureError(
            f"Ed25519 public key must be {ED25519_PUBKEY_LEN} bytes, got {len(ed25519_pk)}",
            error_code="vault.sig.bad_ed25519_pk_length",
        )
    if len(mldsa65_pk) != MLDSA65_PUBKEY_LEN:
        raise SignatureError(
            f"ML-DSA-65 public key must be {MLDSA65_PUBKEY_LEN} bytes, got {len(mldsa65_pk)}",
            error_code="vault.sig.bad_mldsa_pk_length",
        )
    return _pack(ed25519_pk) + _pack(mldsa65_pk)


def parse_public_key(blob: bytes) -> tuple[bytes, bytes]:
    """Parse the hybrid public key envelope back into its components."""
    ed25519_pk, off = _unpack(blob, 0)
    mldsa65_pk, off = _unpack(blob, off)
    if off != len(blob):
        raise SignatureError(
            "trailing bytes after hybrid sig public key",
            error_code="vault.sig.trailing_bytes",
        )
    if len(ed25519_pk) != ED25519_PUBKEY_LEN:
        raise SignatureError(
            f"Ed25519 public key component must be {ED25519_PUBKEY_LEN} bytes, "
            f"got {len(ed25519_pk)}",
            error_code="vault.sig.bad_ed25519_pk_length",
        )
    if len(mldsa65_pk) != MLDSA65_PUBKEY_LEN:
        raise SignatureError(
            f"ML-DSA-65 public key component must be {MLDSA65_PUBKEY_LEN} bytes, "
            f"got {len(mldsa65_pk)}",
            error_code="vault.sig.bad_mldsa_pk_length",
        )
    return ed25519_pk, mldsa65_pk


def _serialize_signature(sig_ed25519: bytes, sig_mldsa65: bytes) -> bytes:
    if len(sig_ed25519) != ED25519_SIGNATURE_LEN:
        raise SignatureError(
            f"Ed25519 signature must be {ED25519_SIGNATURE_LEN} bytes, got {len(sig_ed25519)}",
            error_code="vault.sig.bad_ed25519_sig_length",
        )
    if len(sig_mldsa65) != MLDSA65_SIGNATURE_LEN:
        raise SignatureError(
            f"ML-DSA-65 signature must be {MLDSA65_SIGNATURE_LEN} bytes, got {len(sig_mldsa65)}",
            error_code="vault.sig.bad_mldsa_sig_length",
        )
    return _pack(sig_ed25519) + _pack(sig_mldsa65)


def _parse_signature(blob: bytes) -> tuple[bytes, bytes]:
    sig_ed25519, off = _unpack(blob, 0)
    sig_mldsa65, off = _unpack(blob, off)
    if off != len(blob):
        raise SignatureError(
            "trailing bytes after hybrid signature",
            error_code="vault.sig.trailing_bytes",
        )
    if len(sig_ed25519) != ED25519_SIGNATURE_LEN:
        raise SignatureError(
            f"Ed25519 signature component must be {ED25519_SIGNATURE_LEN} bytes, "
            f"got {len(sig_ed25519)}",
            error_code="vault.sig.bad_ed25519_sig_length",
        )
    if len(sig_mldsa65) != MLDSA65_SIGNATURE_LEN:
        raise SignatureError(
            f"ML-DSA-65 signature component must be {MLDSA65_SIGNATURE_LEN} bytes, "
            f"got {len(sig_mldsa65)}",
            error_code="vault.sig.bad_mldsa_sig_length",
        )
    return sig_ed25519, sig_mldsa65


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_keypair() -> HybridSigKeypair:
    """Generate a fresh hybrid Ed25519 || ML-DSA-65 keypair."""
    oqs = _import_oqs()

    ed_sk = SigningKey.generate()
    ed_sk_raw = ed_sk.to_bytes()
    ed_pk_raw = ed_sk.verify_key.to_bytes()

    with oqs.Signature("ML-DSA-65") as sig:  # type: ignore[attr-defined]
        m_pk_raw = sig.generate_keypair()
        m_sk_raw = sig.export_secret_key()

    if len(m_pk_raw) != MLDSA65_PUBKEY_LEN:  # pragma: no cover - liboqs invariant
        raise SignatureError(
            f"ML-DSA-65 generated public key has wrong length: {len(m_pk_raw)}",
            error_code="vault.sig.bad_mldsa_pk_length",
        )
    if len(m_sk_raw) != MLDSA65_SECRETKEY_LEN:  # pragma: no cover - liboqs invariant
        raise SignatureError(
            f"ML-DSA-65 generated secret key has wrong length: {len(m_sk_raw)}",
            error_code="vault.sig.bad_mldsa_sk_length",
        )

    return HybridSigKeypair(
        ed25519_sk=ed_sk_raw,
        mldsa65_sk=m_sk_raw,
        ed25519_pk=ed_pk_raw,
        mldsa65_pk=m_pk_raw,
    )


def sign(keypair: HybridSigKeypair, message: bytes) -> bytes:
    """Produce a hybrid signature over ``message``.

    Returns
    -------
    bytes
        Length-prefixed envelope ``len(sig_ed25519) || sig_ed25519 ||
        len(sig_mldsa65) || sig_mldsa65``.

    Raises
    ------
    SignatureError
        On any component-level signing failure (malformed key, etc.).
    ConfigurationError
        If liboqs-python is not installed.
    """
    oqs = _import_oqs()

    if len(keypair.ed25519_sk) != ED25519_PUBKEY_LEN:
        raise SignatureError(
            f"Ed25519 secret seed must be {ED25519_PUBKEY_LEN} bytes, "
            f"got {len(keypair.ed25519_sk)}",
            error_code="vault.sig.bad_ed25519_sk_length",
        )
    if len(keypair.mldsa65_sk) != MLDSA65_SECRETKEY_LEN:
        raise SignatureError(
            f"ML-DSA-65 secret key must be {MLDSA65_SECRETKEY_LEN} bytes, "
            f"got {len(keypair.mldsa65_sk)}",
            error_code="vault.sig.bad_mldsa_sk_length",
        )

    ed_sk = SigningKey.from_bytes(keypair.ed25519_sk)
    sig_ed = ed_sk.sign(message)

    with oqs.Signature(  # type: ignore[attr-defined]
        "ML-DSA-65",
        secret_key=keypair.mldsa65_sk,
    ) as signer:
        try:
            sig_m = signer.sign(message)
        except Exception as exc:
            raise SignatureError(
                f"ML-DSA-65 sign failed: {exc}",
                error_code="vault.sig.mldsa_sign_failed",
            ) from exc

    return _serialize_signature(sig_ed, sig_m)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a hybrid signature.

    AND-verify: both component signatures must verify. Returns ``False``
    on any component-level mismatch and raises :class:`SignatureError`
    only for *structural* failures (wrong-length component, malformed
    envelope, malformed key, library failure).

    Parameters
    ----------
    public_key:
        Serialized hybrid public key envelope.
    message:
        The signed message.
    signature:
        Serialized hybrid signature envelope.

    Returns
    -------
    bool
        ``True`` iff both Ed25519 and ML-DSA-65 verifications succeed.

    Raises
    ------
    SignatureError
        On structural / parse failures.
    ConfigurationError
        If liboqs-python is not installed.
    """
    oqs = _import_oqs()
    ed_pk_raw, m_pk_raw = parse_public_key(public_key)
    sig_ed, sig_m = _parse_signature(signature)

    # Classical leg: returns bool.
    ed_vk = VerifyKey.from_bytes(ed_pk_raw)
    classical_ok = ed_vk.verify(message, sig_ed)

    # Post-quantum leg.
    with oqs.Signature("ML-DSA-65") as verifier:  # type: ignore[attr-defined]
        try:
            pq_ok = bool(verifier.verify(message, sig_m, m_pk_raw))
        except Exception as exc:
            raise SignatureError(
                f"ML-DSA-65 verify raised: {exc}",
                error_code="vault.sig.mldsa_verify_failed",
            ) from exc

    return classical_ok and pq_ok
