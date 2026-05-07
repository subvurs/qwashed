# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for :mod:`qwashed.audit.probe_smime` (Qwashed v0.2 §3.2).

Fixtures are generated on the fly using the ``cryptography`` library
(already a Qwashed dep), so the tests are reproducible without checked-in
binary blobs and exercise every supported public-key / signature
combination.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    padding,
    rsa,
)
from cryptography.x509.oid import NameOID

from qwashed.audit.probe_smime import (
    MAX_SMIME_BYTES,
    SmimeProbe,
    parse_smime_certificate,
)
from qwashed.audit.schemas import AuditTarget


# ---------------------------------------------------------------------------
# Fixture builders: build self-signed leaf certs in-memory using
# cryptography. PEM and DER bytes are returned so we can drive both
# encoding paths.
# ---------------------------------------------------------------------------


def _now() -> datetime.datetime:
    return datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


def _name() -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "alice@example.org"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        ]
    )


def _build_self_signed(
    private_key,
    sig_hash=hashes.SHA256(),
    *,
    rsa_pss: bool = False,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name())
        .issuer_name(_name())
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=365))
    )
    # cryptography 41+ takes (private_key, hash, *, rsa_padding=None);
    # for Ed25519, hash must be None and there's no padding parameter.
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return builder.sign(private_key, None)
    if rsa_pss and isinstance(private_key, rsa.RSAPrivateKey):
        return builder.sign(
            private_key,
            sig_hash,
            rsa_padding=padding.PSS(
                mgf=padding.MGF1(sig_hash),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
        )
    return builder.sign(private_key, sig_hash)


def _to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _to_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# parse_smime_certificate
# ---------------------------------------------------------------------------


class TestParseSmimeCertificate:
    def test_rsa_2048_pem(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = _build_self_signed(key)
        info = parse_smime_certificate(_to_pem(cert))
        assert info is not None
        assert info.public_key_algorithm == "rsa_2048"
        assert info.public_key_bits == 2048
        assert info.signature_algorithm == "sha256_with_rsa"

    def test_rsa_2048_der(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = _build_self_signed(key)
        info = parse_smime_certificate(_to_der(cert))
        assert info is not None
        assert info.public_key_algorithm == "rsa_2048"
        assert info.public_key_bits == 2048
        assert info.signature_algorithm == "sha256_with_rsa"

    def test_rsa_3072(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cert = _build_self_signed(key, sig_hash=hashes.SHA384())
        info = parse_smime_certificate(_to_pem(cert))
        assert info is not None
        assert info.public_key_algorithm == "rsa_3072"
        assert info.signature_algorithm == "sha384_with_rsa"

    def test_rsa_pss_sha256(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = _build_self_signed(key, sig_hash=hashes.SHA256(), rsa_pss=True)
        info = parse_smime_certificate(_to_pem(cert))
        assert info is not None
        assert info.public_key_algorithm == "rsa_2048"
        assert info.signature_algorithm == "rsa_pss_sha256"

    def test_rsa_pss_sha384(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cert = _build_self_signed(key, sig_hash=hashes.SHA384(), rsa_pss=True)
        info = parse_smime_certificate(_to_pem(cert))
        assert info is not None
        assert info.signature_algorithm == "rsa_pss_sha384"

    def test_ecdsa_p256(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _build_self_signed(key)
        info = parse_smime_certificate(_to_pem(cert))
        assert info is not None
        assert info.public_key_algorithm == "ecdsa_p256"
        # v0.2 (§3.5): EC keys report curve bit size so the scorer can
        # compare against the ecc_minimum threshold.
        assert info.public_key_bits == 256
        assert info.public_key_family == "ec"
        assert info.signature_algorithm == "ecdsa_with_sha256"

    def test_ecdsa_p384(self) -> None:
        key = ec.generate_private_key(ec.SECP384R1())
        cert = _build_self_signed(key, sig_hash=hashes.SHA384())
        info = parse_smime_certificate(_to_pem(cert))
        assert info is not None
        assert info.public_key_algorithm == "ecdsa_p384"
        assert info.signature_algorithm == "ecdsa_with_sha384"

    def test_ed25519(self) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        cert = _build_self_signed(key)
        info = parse_smime_certificate(_to_pem(cert))
        assert info is not None
        assert info.public_key_algorithm == "ed25519"
        assert info.public_key_bits == 0
        assert info.signature_algorithm == "ed25519"

    def test_garbage_returns_none(self) -> None:
        assert parse_smime_certificate(b"not a certificate") is None

    def test_empty_returns_none(self) -> None:
        assert parse_smime_certificate(b"") is None

    def test_truncated_pem_returns_none(self) -> None:
        # PEM marker but no actual cert body.
        bad = b"-----BEGIN CERTIFICATE-----\nXXXXXX\n-----END CERTIFICATE-----\n"
        assert parse_smime_certificate(bad) is None


# ---------------------------------------------------------------------------
# SmimeProbe end-to-end
# ---------------------------------------------------------------------------


def _smime_target(key_path: str | Path) -> AuditTarget:
    return AuditTarget(  # type: ignore[arg-type]
        host="alice@example.org",
        port=0,
        protocol="smime",
        key_path=str(key_path),
    )


class TestSmimeProbe:
    def test_ok_rsa_pem(self, tmp_path: Path) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = _build_self_signed(key)
        path = tmp_path / "leaf.pem"
        path.write_bytes(_to_pem(cert))

        result = SmimeProbe().probe(_smime_target(path))
        assert result.status == "ok"
        assert result.key_exchange_group == "rsa_2048"
        assert result.signature_algorithm == "sha256_with_rsa"
        assert result.extras.get("smime_public_key_algorithm") == "rsa_2048"
        assert result.extras.get("smime_public_key_bits") == "2048"

    def test_ok_ecdsa_der(self, tmp_path: Path) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _build_self_signed(key)
        path = tmp_path / "leaf.der"
        path.write_bytes(_to_der(cert))

        result = SmimeProbe().probe(_smime_target(path))
        assert result.status == "ok"
        assert result.key_exchange_group == "ecdsa_p256"
        assert result.signature_algorithm == "ecdsa_with_sha256"

    def test_ok_ed25519(self, tmp_path: Path) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        cert = _build_self_signed(key)
        path = tmp_path / "leaf.pem"
        path.write_bytes(_to_pem(cert))

        result = SmimeProbe().probe(_smime_target(path))
        assert result.status == "ok"
        assert result.key_exchange_group == "ed25519"
        assert result.signature_algorithm == "ed25519"

    def test_unreachable_when_file_missing(self, tmp_path: Path) -> None:
        result = SmimeProbe().probe(_smime_target(tmp_path / "nope.pem"))
        assert result.status == "unreachable"
        assert "cannot read" in (result.error_detail or "")

    def test_malformed_when_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.pem"
        path.write_bytes(b"")
        result = SmimeProbe().probe(_smime_target(path))
        assert result.status == "malformed"
        assert "empty" in (result.error_detail or "")

    def test_malformed_when_garbage(self, tmp_path: Path) -> None:
        path = tmp_path / "garbage.pem"
        path.write_bytes(b"this is not a certificate at all")
        result = SmimeProbe().probe(_smime_target(path))
        assert result.status == "malformed"
        assert "PEM or DER" in (result.error_detail or "")

    def test_malformed_when_oversize(self, tmp_path: Path) -> None:
        path = tmp_path / "huge.pem"
        path.write_bytes(b"X" * (MAX_SMIME_BYTES + 1))
        result = SmimeProbe().probe(_smime_target(path))
        assert result.status == "malformed"
        assert str(MAX_SMIME_BYTES) in (result.error_detail or "")

    def test_malformed_on_wrong_protocol(self) -> None:
        target = AuditTarget(host="x.example", port=443, protocol="tls")
        result = SmimeProbe().probe(target)
        assert result.status == "malformed"
        assert "not supported" in (result.error_detail or "")

    def test_schema_rejects_smime_without_key_path(self) -> None:
        # Defense in depth: the AuditTarget validator rejects file-only
        # protocols that lack ``key_path`` at construction time, so the
        # probe's internal "missing key_path" branch is unreachable in
        # the normal flow. Verify that the validator does the rejecting.
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            AuditTarget(  # type: ignore[arg-type]
                host="alice@example.org",
                port=0,
                protocol="smime",
                key_path=None,
            )

    def test_dsa_classified_when_present(self, tmp_path: Path) -> None:
        # DSA is rare but supported; verify the bucketing path runs.
        params = dsa.generate_parameters(key_size=2048)
        key = params.generate_private_key()
        cert = _build_self_signed(key)
        path = tmp_path / "dsa.pem"
        path.write_bytes(_to_pem(cert))
        result = SmimeProbe().probe(_smime_target(path))
        assert result.status == "ok"
        assert result.key_exchange_group == "dsa_2048"
