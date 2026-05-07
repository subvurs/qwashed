# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""S/MIME (X.509 certificate) public-key probe for the Qwashed HNDL
auditor (§3.2).

Why ``cryptography``?
---------------------
S/MIME identities are X.509 certificates. ``cryptography`` (already a
required Qwashed dependency for Ed25519 artifact signing) ships a
deterministic, well-tested DER/PEM parser. There is no upside to
hand-rolling X.509 — unlike OpenPGP, the format is huge, and the parser
needs to handle a long tail of curve identifiers, signature OIDs, and
SubjectPublicKeyInfo encodings the cryptography backends already
normalize for us.

Hard guarantees
---------------
* No network access. Ever. (No CRL / OCSP fetch, no AIA chasing.)
* Reads at most :data:`MAX_SMIME_BYTES` from disk.
* Never raises on a malformed certificate: returns ``status="malformed"``
  with a summary ``error_detail`` string.
* Does *not* validate the certificate chain, expiry, or revocation —
  this is a posture classifier, not a trust evaluator. Surfacing chain
  validity is on the §3.x roadmap; for now we report the leaf cert's
  algorithms and let the auditor downstream decide.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)

from qwashed.audit.probe_base import Probe
from qwashed.audit.schemas import AuditTarget, ProbeResult

__all__ = [
    "MAX_SMIME_BYTES",
    "SmimeCertInfo",
    "SmimeProbe",
    "parse_smime_certificate",
]

#: Hard ceiling on S/MIME certificate file size. Even the largest
#: deployed RSA-8192 leaf certs sit well under 16 KiB; we cap at 1 MiB
#: to refuse pathological inputs without rejecting legitimate cert
#: bundles.
MAX_SMIME_BYTES: Final[int] = 1_048_576


# OIDs we map to friendly signature-algorithm names. These are the
# ``signatureAlgorithm`` (and ``signature``) values that appear on
# S/MIME-issued leaf certificates in the wild. Anything not in this
# table is reported as the dotted OID string and the classifier will
# fall back to ``unknown``.
#
# Source: RFC 5754 (SHA-2 for CMS), RFC 8410 (Ed25519/Ed448 in PKIX),
# RFC 8702 (rsa_pss in PKIX), various IANA registries.
_SIG_OID_TO_NAME: Final[dict[str, str]] = {
    # PKCS#1 v1.5 RSA
    "1.2.840.113549.1.1.4": "md5_with_rsa",
    "1.2.840.113549.1.1.5": "sha1_with_rsa",
    "1.2.840.113549.1.1.11": "sha256_with_rsa",
    "1.2.840.113549.1.1.12": "sha384_with_rsa",
    "1.2.840.113549.1.1.13": "sha512_with_rsa",
    # RSASSA-PSS (parameters distinguish the hash; we report the
    # canonical sha256 default; see _refine_rsa_pss for the override).
    "1.2.840.113549.1.1.10": "rsa_pss_sha256",
    # ECDSA
    "1.2.840.10045.4.1": "sha1_with_ecdsa",
    "1.2.840.10045.4.3.2": "ecdsa_with_sha256",
    "1.2.840.10045.4.3.3": "ecdsa_with_sha384",
    "1.2.840.10045.4.3.4": "ecdsa_with_sha512",
    # EdDSA (RFC 8410)
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
    # DSA
    "1.2.840.10040.4.3": "sha1_with_dsa",
    "2.16.840.1.101.3.4.3.2": "sha256_with_dsa",
}

# EC named-curve OIDs to the Qwashed wire-name (matches the smime tables
# in algorithm_tables.json).
_EC_CURVE_TO_NAME: Final[dict[str, str]] = {
    "secp256r1": "ecdsa_p256",
    "secp384r1": "ecdsa_p384",
    "secp521r1": "ecdsa_p521",
    "brainpoolP256r1": "ecdsa_brainpoolp256r1",
    "brainpoolP384r1": "ecdsa_brainpoolp384r1",
    "brainpoolP512r1": "ecdsa_brainpoolp512r1",
}


@dataclass(frozen=True)
class SmimeCertInfo:
    """Result of classifying an S/MIME X.509 leaf certificate.

    Attributes
    ----------
    public_key_algorithm:
        Wire-name of the SubjectPublicKeyInfo algorithm, e.g.
        ``"rsa_2048"``, ``"ecdsa_p256"``, ``"ed25519"``. Empty if the
        public-key type is not recognized.
    signature_algorithm:
        Wire-name of the cert's ``signatureAlgorithm`` field, e.g.
        ``"sha256_with_rsa"``, ``"ecdsa_with_sha256"``, ``"ed25519"``,
        ``"rsa_pss_sha256"``. Empty if not recognized.
    public_key_bits:
        For RSA / DSA, the modulus bit length (exact, not bucketed).
        For EC, the curve bit size (e.g. 256 for P-256). Zero for
        fixed-size algorithms (Ed25519, Ed448, X25519, X448).
    public_key_family:
        Coarse family used by the v0.2 scoring layer:
        ``"rsa"``, ``"dsa"``, ``"ec"``, ``"ed25519"``, ``"ed448"``,
        ``"x25519"``, ``"x448"``, or ``""`` for unknown.
    not_after:
        Cert NotAfter as ISO 8601 ``YYYY-MM-DD`` (UTC), or ``None`` if
        unparseable.
    """

    public_key_algorithm: str
    signature_algorithm: str
    public_key_bits: int = 0
    public_key_family: str = ""
    not_after: str | None = None


def _bucket_rsa_bits(bits: int) -> str:
    for bucket in (1024, 2048, 3072, 4096, 8192):
        if bits <= bucket + 8:
            return f"rsa_{bucket}"
    return f"rsa_{bits}"


def _bucket_dsa_bits(bits: int) -> str:
    for bucket in (1024, 2048, 3072):
        if bits <= bucket + 8:
            return f"dsa_{bucket}"
    return f"dsa_{bits}"


def _classify_public_key(
    cert: x509.Certificate,
) -> tuple[str, int, str]:
    """Return ``(wire_name, bit_length, family)`` for the cert's public key.

    ``bit_length`` is the RSA modulus / DSA p length / EC curve bit size.
    Returns 0 for fixed-size algorithms (Ed25519/Ed448/X25519/X448).
    ``wire_name`` is empty for unrecognized key types.
    ``family`` is the coarse :attr:`SmimeCertInfo.public_key_family`
    used by the v0.2 scorer.
    """
    try:
        public_key = cert.public_key()
    except (ValueError, UnsupportedAlgorithm):
        return ("", 0, "")

    if isinstance(public_key, rsa.RSAPublicKey):
        bits = public_key.key_size
        return (_bucket_rsa_bits(bits), bits, "rsa")
    if isinstance(public_key, dsa.DSAPublicKey):
        bits = public_key.key_size
        return (_bucket_dsa_bits(bits), bits, "dsa")
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        wire = _EC_CURVE_TO_NAME.get(curve_name, "")
        return (wire, public_key.curve.key_size, "ec")
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return ("ed25519", 0, "ed25519")
    if isinstance(public_key, ed448.Ed448PublicKey):
        return ("ed448", 0, "ed448")
    if isinstance(public_key, x25519.X25519PublicKey):
        return ("x25519", 0, "x25519")
    if isinstance(public_key, x448.X448PublicKey):
        return ("x448", 0, "x448")
    return ("", 0, "")


def _smime_not_after_iso(cert: x509.Certificate) -> str | None:
    try:
        when = cert.not_valid_after_utc  # cryptography >= 42
    except AttributeError:  # pragma: no cover - legacy cryptography
        when = cert.not_valid_after
    if when is None:
        return None
    return when.strftime("%Y-%m-%d")


def _refine_rsa_pss(cert: x509.Certificate, fallback: str) -> str:
    """If the cert is signed with RSASSA-PSS, refine the signature
    name to include the hash actually parameterized in the cert.

    ``cryptography`` exposes ``signature_hash_algorithm`` for PSS
    certs; the OID alone does not encode the hash. Falls back to
    ``fallback`` (the OID-table default ``"rsa_pss_sha256"``) if the
    hash cannot be determined.
    """
    try:
        h = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        return fallback
    if h is None:
        return fallback
    name = h.name.lower()
    if name in ("sha256", "sha384", "sha512"):
        return f"rsa_pss_{name}"
    return fallback


def _classify_signature(cert: x509.Certificate) -> str:
    """Return a wire-name for the cert's signature algorithm."""
    try:
        oid = cert.signature_algorithm_oid
    except (ValueError, UnsupportedAlgorithm):
        return ""
    dotted = oid.dotted_string
    name = _SIG_OID_TO_NAME.get(dotted, "")
    if name == "rsa_pss_sha256":
        return _refine_rsa_pss(cert, name)
    if name:
        return name
    return ""


def parse_smime_certificate(data: bytes) -> SmimeCertInfo | None:
    """Parse an X.509 certificate (PEM or DER) and classify it.

    Returns ``None`` if neither encoding loads. Never raises.
    """
    cert: x509.Certificate | None = None
    # Try PEM first: PEM files start with '-----BEGIN'. Falling through
    # to DER if the PEM loader rejects the bytes is correct because
    # cryptography raises ValueError on a non-PEM blob.
    try:
        cert = x509.load_pem_x509_certificate(data)
    except (ValueError, UnsupportedAlgorithm):
        cert = None
    if cert is None:
        try:
            cert = x509.load_der_x509_certificate(data)
        except (ValueError, UnsupportedAlgorithm):
            cert = None
    if cert is None:
        return None

    pub_name, pub_bits, pub_family = _classify_public_key(cert)
    sig_name = _classify_signature(cert)
    return SmimeCertInfo(
        public_key_algorithm=pub_name,
        signature_algorithm=sig_name,
        public_key_bits=pub_bits,
        public_key_family=pub_family,
        not_after=_smime_not_after_iso(cert),
    )


class SmimeProbe(Probe):
    """File-only probe of an S/MIME (X.509) certificate.

    Reads :attr:`AuditTarget.key_path`, parses the leaf certificate,
    and reports both the SubjectPublicKeyInfo algorithm (in
    :attr:`ProbeResult.key_exchange_group` — repurposed as "the
    algorithm of the key the relying party will encrypt to") and the
    cert's signature algorithm (in
    :attr:`ProbeResult.signature_algorithm`).
    """

    def probe(self, target: AuditTarget) -> ProbeResult:
        if target.protocol != "smime":
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=(
                    f"protocol={target.protocol!r} not supported by SmimeProbe"
                ),
            )
        if not target.key_path:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail="smime target missing key_path",
            )
        start = time.monotonic()
        path = Path(target.key_path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            return ProbeResult(
                target=target,
                status="unreachable",
                error_detail=(
                    f"cannot read smime certificate: {type(exc).__name__}: {exc}"
                ),
                elapsed_seconds=time.monotonic() - start,
            )
        if not data:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail="smime certificate file is empty",
                elapsed_seconds=time.monotonic() - start,
            )
        if len(data) > MAX_SMIME_BYTES:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=(
                    f"smime certificate file exceeds {MAX_SMIME_BYTES}-byte cap;"
                    " refusing"
                ),
                elapsed_seconds=time.monotonic() - start,
            )
        info = parse_smime_certificate(data)
        elapsed = time.monotonic() - start
        if info is None:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail="could not parse certificate as PEM or DER",
                elapsed_seconds=elapsed,
            )
        extras: dict[str, str] = {}
        if info.public_key_algorithm:
            extras["smime_public_key_algorithm"] = info.public_key_algorithm
        if info.public_key_bits:
            extras["smime_public_key_bits"] = str(info.public_key_bits)
        return ProbeResult(
            target=target,
            status="ok",
            key_exchange_group=info.public_key_algorithm,
            signature_algorithm=info.signature_algorithm,
            extras=extras,
            public_key_bits=(
                info.public_key_bits if info.public_key_bits else None
            ),
            public_key_algorithm_family=(
                info.public_key_family or None
            ),
            cert_not_after=info.not_after,
            elapsed_seconds=elapsed,
        )
