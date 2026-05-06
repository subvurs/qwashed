# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Hybrid X25519 || ML-KEM-768 key encapsulation mechanism.

This module wraps two component KEMs into a single hybrid KEM whose
shared secret is bound to *both* component shared secrets. An attacker
must break both X25519 (classical ECDH) and ML-KEM-768 (NIST FIPS 203)
to recover the derived secret. This is the "hedge" posture that lets
Qwashed be safe today (X25519 is well-understood) and safe against
harvest-now-decrypt-later attacks (ML-KEM-768 is post-quantum).

Construction
------------
- Encapsulator runs both X25519 ECDH and ML-KEM-768 ``encap`` against
  the recipient's public key, producing two shared secrets.
- Decapsulator runs both X25519 ECDH and ML-KEM-768 ``decap`` against
  its private key, producing two shared secrets.
- Both sides combine via:

    ss = HKDF-SHA256(
        ikm  = ss_x25519 || ss_mlkem768,
        salt = b"",
        info = b"qwashed/vault/v0.1/kem",
        length = 32,
    )

Wire format
-----------
The ciphertext envelope is length-prefixed so we can recover both
components without knowing their fixed sizes a priori::

    ct = u32_be(len(ct_x25519)) || ct_x25519
       || u32_be(len(ct_mlkem768)) || ct_mlkem768

Where ``ct_x25519`` is the ephemeral X25519 public key (32 bytes) and
``ct_mlkem768`` is the ML-KEM-768 ciphertext (1088 bytes per FIPS 203).

Public-key envelope is symmetric::

    pk = u32_be(len(pk_x25519)) || pk_x25519
       || u32_be(len(pk_mlkem768)) || pk_mlkem768

Where ``pk_x25519`` is 32 bytes and ``pk_mlkem768`` is 1184 bytes.

Fail-closed posture
-------------------
- Truncated / malformed envelope -> :class:`SignatureError`.
- Length prefix that overruns the buffer -> :class:`SignatureError`.
- Component pubkey of wrong length -> :class:`SignatureError`.
- ML-KEM not available (liboqs missing) -> :class:`ConfigurationError`.

There is no "best-effort, fall back to classical only" mode. If the
post-quantum component is missing or fails, the hybrid operation fails.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from qwashed.core.errors import ConfigurationError, SignatureError
from qwashed.core.kdf import hkdf_sha256, info_for

__all__ = [
    "HYBRID_KEM_INFO",
    "HYBRID_KEM_INFO_V01",
    "HYBRID_KEM_INFO_V02",
    "HYBRID_KEM_SHARED_SECRET_LEN",
    "MLKEM768_CIPHERTEXT_LEN",
    "MLKEM768_PUBKEY_LEN",
    "MLKEM768_SECRETKEY_LEN",
    "MLKEM768_SHARED_SECRET_LEN",
    "X25519_PUBKEY_LEN",
    "HybridKemKeypair",
    "decapsulate",
    "encapsulate",
    "generate_keypair",
    "kem_info_for_format",
    "parse_public_key",
    "serialize_public_key",
]

#: ML-KEM-768 public key length per NIST FIPS 203.
MLKEM768_PUBKEY_LEN: Final[int] = 1184

#: ML-KEM-768 secret key length per NIST FIPS 203.
MLKEM768_SECRETKEY_LEN: Final[int] = 2400

#: ML-KEM-768 ciphertext length per NIST FIPS 203.
MLKEM768_CIPHERTEXT_LEN: Final[int] = 1088

#: ML-KEM-768 shared-secret length per NIST FIPS 203.
MLKEM768_SHARED_SECRET_LEN: Final[int] = 32

#: X25519 raw public key length per RFC 7748.
X25519_PUBKEY_LEN: Final[int] = 32

#: Final hybrid shared-secret length (HKDF output).
HYBRID_KEM_SHARED_SECRET_LEN: Final[int] = 32

#: Canonical HKDF info string for the hybrid combiner -- vault format v0.1.
HYBRID_KEM_INFO_V01: Final[bytes] = info_for(module="vault", purpose="kem", version="v0.1")

#: Canonical HKDF info string for the hybrid combiner -- vault format v0.2.
HYBRID_KEM_INFO_V02: Final[bytes] = info_for(module="vault", purpose="kem", version="v0.2")

#: Backwards-compatible alias for v0.1 callers (pre-format-version code).
HYBRID_KEM_INFO: Final[bytes] = HYBRID_KEM_INFO_V01


def kem_info_for_format(format_version: int) -> bytes:
    """Return the HKDF info string for a given vault ``format_version``.

    Parameters
    ----------
    format_version:
        Vault format version. ``1`` for v0.1 vaults, ``2`` for v0.2 vaults.

    Raises
    ------
    SignatureError
        If ``format_version`` is not in ``{1, 2}``.
    """
    if format_version == 1:
        return HYBRID_KEM_INFO_V01
    if format_version == 2:
        return HYBRID_KEM_INFO_V02
    raise SignatureError(
        f"unsupported vault format_version: {format_version}",
        error_code="vault.kem.bad_format_version",
    )

#: Maximum sane component length used for malformed-input rejection.
_MAX_COMPONENT_LEN: Final[int] = 1 << 20  # 1 MiB; far above any FIPS sizes.


def _import_oqs() -> object:
    """Import liboqs lazily and surface a fail-closed configuration error."""
    try:
        import oqs
    except ImportError as exc:  # pragma: no cover - exercised by CI without extras
        raise ConfigurationError(
            "liboqs-python is required for ML-KEM-768; install qwashed[vault]",
            error_code="vault.kem.missing_oqs",
        ) from exc
    return oqs


@dataclass(frozen=True)
class HybridKemKeypair:
    """A hybrid X25519 || ML-KEM-768 keypair.

    Both component secrets must be present together. Splitting them is a
    contract violation: a hybrid identity is not safe if only the classical
    half remains.

    Attributes
    ----------
    x25519_sk:
        Raw 32-byte X25519 private scalar.
    mlkem768_sk:
        Raw ML-KEM-768 secret key (FIPS 203, 2400 bytes).
    x25519_pk:
        Raw 32-byte X25519 public key.
    mlkem768_pk:
        Raw ML-KEM-768 public key (FIPS 203, 1184 bytes).
    """

    x25519_sk: bytes
    mlkem768_sk: bytes
    x25519_pk: bytes
    mlkem768_pk: bytes

    def public_bytes(self) -> bytes:
        """Return the serialized hybrid public key envelope."""
        return serialize_public_key(self.x25519_pk, self.mlkem768_pk)


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------


def _pack(component: bytes) -> bytes:
    if len(component) > _MAX_COMPONENT_LEN:
        raise SignatureError(
            f"hybrid KEM component too large: {len(component)} bytes",
            error_code="vault.kem.component_too_large",
        )
    return struct.pack(">I", len(component)) + component


def _unpack(buffer: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(buffer):
        raise SignatureError(
            "hybrid KEM envelope truncated at length prefix",
            error_code="vault.kem.truncated_length",
        )
    (length,) = struct.unpack(">I", buffer[offset : offset + 4])
    if length > _MAX_COMPONENT_LEN:
        raise SignatureError(
            f"hybrid KEM envelope length out of range: {length}",
            error_code="vault.kem.bad_length",
        )
    start = offset + 4
    end = start + length
    if end > len(buffer):
        raise SignatureError(
            "hybrid KEM envelope truncated at component body",
            error_code="vault.kem.truncated_body",
        )
    return buffer[start:end], end


def serialize_public_key(x25519_pk: bytes, mlkem768_pk: bytes) -> bytes:
    """Serialize the hybrid public key into the canonical wire format.

    Parameters
    ----------
    x25519_pk:
        Raw 32-byte X25519 public key.
    mlkem768_pk:
        Raw 1184-byte ML-KEM-768 public key.

    Raises
    ------
    SignatureError
        If either component has the wrong length.
    """
    if len(x25519_pk) != X25519_PUBKEY_LEN:
        raise SignatureError(
            f"X25519 public key must be {X25519_PUBKEY_LEN} bytes, got {len(x25519_pk)}",
            error_code="vault.kem.bad_x25519_pk_length",
        )
    if len(mlkem768_pk) != MLKEM768_PUBKEY_LEN:
        raise SignatureError(
            f"ML-KEM-768 public key must be {MLKEM768_PUBKEY_LEN} bytes, got {len(mlkem768_pk)}",
            error_code="vault.kem.bad_mlkem_pk_length",
        )
    return _pack(x25519_pk) + _pack(mlkem768_pk)


def parse_public_key(blob: bytes) -> tuple[bytes, bytes]:
    """Parse the hybrid public key envelope back into its components.

    Returns
    -------
    tuple[bytes, bytes]
        ``(x25519_pk, mlkem768_pk)``.

    Raises
    ------
    SignatureError
        If ``blob`` is truncated, has trailing data, or component lengths
        do not match the expected fixed sizes.
    """
    x25519_pk, off = _unpack(blob, 0)
    mlkem768_pk, off = _unpack(blob, off)
    if off != len(blob):
        raise SignatureError(
            "trailing bytes after hybrid KEM public key",
            error_code="vault.kem.trailing_bytes",
        )
    if len(x25519_pk) != X25519_PUBKEY_LEN:
        raise SignatureError(
            f"X25519 public key component must be {X25519_PUBKEY_LEN} bytes, got {len(x25519_pk)}",
            error_code="vault.kem.bad_x25519_pk_length",
        )
    if len(mlkem768_pk) != MLKEM768_PUBKEY_LEN:
        raise SignatureError(
            f"ML-KEM-768 public key component must be {MLKEM768_PUBKEY_LEN} bytes, "
            f"got {len(mlkem768_pk)}",
            error_code="vault.kem.bad_mlkem_pk_length",
        )
    return x25519_pk, mlkem768_pk


def _serialize_ciphertext(ct_x25519: bytes, ct_mlkem768: bytes) -> bytes:
    if len(ct_x25519) != X25519_PUBKEY_LEN:
        raise SignatureError(
            f"X25519 ephemeral pubkey must be {X25519_PUBKEY_LEN} bytes, got {len(ct_x25519)}",
            error_code="vault.kem.bad_x25519_ct_length",
        )
    if len(ct_mlkem768) != MLKEM768_CIPHERTEXT_LEN:
        raise SignatureError(
            f"ML-KEM-768 ciphertext must be {MLKEM768_CIPHERTEXT_LEN} bytes, "
            f"got {len(ct_mlkem768)}",
            error_code="vault.kem.bad_mlkem_ct_length",
        )
    return _pack(ct_x25519) + _pack(ct_mlkem768)


def _parse_ciphertext(blob: bytes) -> tuple[bytes, bytes]:
    ct_x25519, off = _unpack(blob, 0)
    ct_mlkem768, off = _unpack(blob, off)
    if off != len(blob):
        raise SignatureError(
            "trailing bytes after hybrid KEM ciphertext",
            error_code="vault.kem.trailing_bytes",
        )
    if len(ct_x25519) != X25519_PUBKEY_LEN:
        raise SignatureError(
            f"X25519 ephemeral pubkey component must be {X25519_PUBKEY_LEN} bytes, "
            f"got {len(ct_x25519)}",
            error_code="vault.kem.bad_x25519_ct_length",
        )
    if len(ct_mlkem768) != MLKEM768_CIPHERTEXT_LEN:
        raise SignatureError(
            f"ML-KEM-768 ciphertext component must be {MLKEM768_CIPHERTEXT_LEN} bytes, "
            f"got {len(ct_mlkem768)}",
            error_code="vault.kem.bad_mlkem_ct_length",
        )
    return ct_x25519, ct_mlkem768


# ---------------------------------------------------------------------------
# Combiner
# ---------------------------------------------------------------------------


def _combine(
    ss_x25519: bytes,
    ss_mlkem768: bytes,
    *,
    format_version: int = 1,
) -> bytes:
    if len(ss_x25519) != X25519_PUBKEY_LEN:
        raise SignatureError(
            f"X25519 shared secret must be {X25519_PUBKEY_LEN} bytes, got {len(ss_x25519)}",
            error_code="vault.kem.bad_x25519_ss_length",
        )
    if len(ss_mlkem768) != MLKEM768_SHARED_SECRET_LEN:
        raise SignatureError(
            f"ML-KEM-768 shared secret must be {MLKEM768_SHARED_SECRET_LEN} bytes, "
            f"got {len(ss_mlkem768)}",
            error_code="vault.kem.bad_mlkem_ss_length",
        )
    return hkdf_sha256(
        ikm=ss_x25519 + ss_mlkem768,
        salt=b"",
        info=kem_info_for_format(format_version),
        length=HYBRID_KEM_SHARED_SECRET_LEN,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_keypair() -> HybridKemKeypair:
    """Generate a fresh hybrid X25519 || ML-KEM-768 keypair.

    Returns
    -------
    HybridKemKeypair
        Both component secrets and public keys.

    Raises
    ------
    ConfigurationError
        If liboqs-python is not installed.
    """
    oqs = _import_oqs()

    x_sk = X25519PrivateKey.generate()
    x_sk_raw = x_sk.private_bytes_raw()
    x_pk_raw = x_sk.public_key().public_bytes_raw()

    with oqs.KeyEncapsulation("ML-KEM-768") as kem:  # type: ignore[attr-defined]
        m_pk_raw = kem.generate_keypair()
        m_sk_raw = kem.export_secret_key()

    if len(m_pk_raw) != MLKEM768_PUBKEY_LEN:  # pragma: no cover - liboqs invariant
        raise SignatureError(
            f"ML-KEM-768 generated public key has wrong length: {len(m_pk_raw)}",
            error_code="vault.kem.bad_mlkem_pk_length",
        )
    if len(m_sk_raw) != MLKEM768_SECRETKEY_LEN:  # pragma: no cover - liboqs invariant
        raise SignatureError(
            f"ML-KEM-768 generated secret key has wrong length: {len(m_sk_raw)}",
            error_code="vault.kem.bad_mlkem_sk_length",
        )

    return HybridKemKeypair(
        x25519_sk=x_sk_raw,
        mlkem768_sk=m_sk_raw,
        x25519_pk=x_pk_raw,
        mlkem768_pk=m_pk_raw,
    )


def encapsulate(
    recipient_public: bytes,
    *,
    format_version: int = 1,
) -> tuple[bytes, bytes]:
    """Encapsulate a fresh hybrid shared secret to ``recipient_public``.

    Parameters
    ----------
    recipient_public:
        Serialized hybrid public key envelope (see :func:`parse_public_key`).
    format_version:
        Vault format version controlling the HKDF info string used by the
        combiner. ``1`` for v0.1 vaults, ``2`` for v0.2 vaults. The wire
        format of the ciphertext envelope is identical across versions;
        only the derived shared secret differs (domain separation).

    Returns
    -------
    tuple[bytes, bytes]
        ``(ciphertext_envelope, shared_secret)``. The ciphertext envelope
        is intended to be transmitted alongside the AEAD payload; the
        shared secret is the symmetric key (or feeds an AEAD KDF).

    Raises
    ------
    SignatureError
        On malformed recipient public-key envelope, or unsupported
        ``format_version``.
    ConfigurationError
        If liboqs-python is not installed.
    """
    x_pk_raw, m_pk_raw = parse_public_key(recipient_public)

    oqs = _import_oqs()

    # Classical leg.
    eph = X25519PrivateKey.generate()
    eph_pub_raw = eph.public_key().public_bytes_raw()
    try:
        peer_x = X25519PublicKey.from_public_bytes(x_pk_raw)
    except Exception as exc:
        raise SignatureError(
            f"failed to parse X25519 public key: {exc}",
            error_code="vault.kem.bad_x25519_pk",
        ) from exc
    ss_x = eph.exchange(peer_x)

    # Post-quantum leg.
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:  # type: ignore[attr-defined]
        try:
            ct_m, ss_m = kem.encap_secret(m_pk_raw)
        except Exception as exc:
            raise SignatureError(
                f"ML-KEM-768 encap failed: {exc}",
                error_code="vault.kem.encap_failed",
            ) from exc

    ct = _serialize_ciphertext(eph_pub_raw, ct_m)
    ss = _combine(ss_x, ss_m, format_version=format_version)
    return ct, ss


def decapsulate(
    keypair: HybridKemKeypair,
    ciphertext: bytes,
    *,
    format_version: int = 1,
) -> bytes:
    """Decapsulate the hybrid shared secret using ``keypair``'s private keys.

    Parameters
    ----------
    keypair:
        The recipient's :class:`HybridKemKeypair` (private material required).
    ciphertext:
        Length-prefixed envelope produced by :func:`encapsulate`.
    format_version:
        Vault format version controlling the HKDF info string used by the
        combiner. ``1`` for v0.1 vaults, ``2`` for v0.2 vaults. The caller
        must know this value (e.g. from the blob header byte) -- mismatch
        produces an unrelated 32-byte derived key, which then fails AEAD
        verification at the next layer.

    Returns
    -------
    bytes
        The 32-byte hybrid shared secret. Must match the encapsulator's.

    Raises
    ------
    SignatureError
        On malformed ciphertext envelope, malformed key, component decap
        failure, or unsupported ``format_version``.
    ConfigurationError
        If liboqs-python is not installed.
    """
    ct_x, ct_m = _parse_ciphertext(ciphertext)

    oqs = _import_oqs()

    # Classical leg.
    if len(keypair.x25519_sk) != X25519_PUBKEY_LEN:
        raise SignatureError(
            f"X25519 secret key must be {X25519_PUBKEY_LEN} bytes, got {len(keypair.x25519_sk)}",
            error_code="vault.kem.bad_x25519_sk_length",
        )
    try:
        sk_x = X25519PrivateKey.from_private_bytes(keypair.x25519_sk)
        peer = X25519PublicKey.from_public_bytes(ct_x)
        ss_x = sk_x.exchange(peer)
    except SignatureError:
        raise
    except Exception as exc:
        raise SignatureError(
            f"X25519 decap failed: {exc}",
            error_code="vault.kem.x25519_decap_failed",
        ) from exc

    # Post-quantum leg.
    if len(keypair.mlkem768_sk) != MLKEM768_SECRETKEY_LEN:
        raise SignatureError(
            f"ML-KEM-768 secret key must be {MLKEM768_SECRETKEY_LEN} bytes, "
            f"got {len(keypair.mlkem768_sk)}",
            error_code="vault.kem.bad_mlkem_sk_length",
        )
    with oqs.KeyEncapsulation(  # type: ignore[attr-defined]
        "ML-KEM-768",
        secret_key=keypair.mlkem768_sk,
    ) as kem:
        try:
            ss_m = kem.decap_secret(ct_m)
        except Exception as exc:
            raise SignatureError(
                f"ML-KEM-768 decap failed: {exc}",
                error_code="vault.kem.mlkem_decap_failed",
            ) from exc

    return _combine(ss_x, ss_m, format_version=format_version)
