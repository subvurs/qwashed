# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.audit.classifier."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from qwashed.audit.classifier import (
    classify,
    classify_algorithm,
    load_algorithm_tables,
)
from qwashed.audit.schemas import AuditTarget, ProbeResult
from qwashed.core.errors import ConfigurationError


def _tls_target() -> AuditTarget:
    return AuditTarget(host="x.example", port=443, protocol="tls")


def _ssh_target() -> AuditTarget:
    return AuditTarget(host="x.example", port=22, protocol="ssh")


def _pgp_target() -> AuditTarget:
    return AuditTarget(  # type: ignore[arg-type]
        host="alice@example.org",
        port=0,
        protocol="pgp",
        key_path="/tmp/dummy.asc",
    )


def _smime_target() -> AuditTarget:
    return AuditTarget(  # type: ignore[arg-type]
        host="alice@example.org",
        port=0,
        protocol="smime",
        key_path="/tmp/dummy.pem",
    )


def _probe_ok(
    target: AuditTarget,
    *,
    kex: str = "",
    sig: str = "",
    cipher: str = "",
) -> ProbeResult:
    return ProbeResult(
        target=target,
        status="ok",
        negotiated_protocol_version="TLSv1.3" if target.protocol == "tls" else "SSH-2.0",
        cipher_suite=cipher,
        key_exchange_group=kex,
        signature_algorithm=sig,
    )


class TestAlgorithmTables:
    def test_loaded(self) -> None:
        t = load_algorithm_tables()
        assert t.classify_tls_kex("X25519") == "classical"
        assert t.classify_tls_kex("X25519MLKEM768") == "hybrid_pq"
        assert t.classify_tls_kex("MLKEM768") == "pq_only"

    def test_case_insensitive_tls_kex(self) -> None:
        t = load_algorithm_tables()
        assert t.classify_tls_kex("x25519") == "classical"
        assert t.classify_tls_kex("X25519") == "classical"
        assert t.classify_tls_kex(" X25519 ") == "classical"

    def test_case_sensitive_cipher(self) -> None:
        t = load_algorithm_tables()
        assert t.classify_tls_cipher("TLS_AES_128_GCM_SHA256") == "classical"
        # Lowercase is not in the table because IANA uses upper snake case.
        assert t.classify_tls_cipher("tls_aes_128_gcm_sha256") == "unknown"

    def test_unknown_returns_unknown(self) -> None:
        t = load_algorithm_tables()
        assert t.classify_tls_kex("FrobnicatorEC448") == "unknown"
        assert t.classify_tls_signature("imaginary_sig_v9") == "unknown"
        assert t.classify_ssh_kex("imaginary-kex") == "unknown"

    def test_ssh(self) -> None:
        t = load_algorithm_tables()
        assert t.classify_ssh_kex("curve25519-sha256") == "classical"
        assert t.classify_ssh_kex("sntrup761x25519-sha512") == "hybrid_pq"
        assert t.classify_ssh_hostkey("ssh-ed25519") == "classical"

    def test_pgp_public_key(self) -> None:
        t = load_algorithm_tables()
        assert t.classify_pgp_public_key("rsa_2048") == "classical"
        assert t.classify_pgp_public_key("ed25519") == "classical"
        assert t.classify_pgp_public_key("garbage_algo") == "unknown"

    def test_smime_public_key(self) -> None:
        t = load_algorithm_tables()
        assert t.classify_smime_public_key("rsa_2048") == "classical"
        assert t.classify_smime_public_key("ecdsa_p256") == "classical"
        assert t.classify_smime_public_key("garbage_algo") == "unknown"

    def test_smime_signature(self) -> None:
        t = load_algorithm_tables()
        assert t.classify_smime_signature("sha256_with_rsa") == "classical"
        assert t.classify_smime_signature("ecdsa_with_sha256") == "classical"
        assert t.classify_smime_signature("ed25519") == "classical"
        assert t.classify_smime_signature("garbage_sig") == "unknown"


class TestClassifyAlgorithm:
    def test_tls_kex(self) -> None:
        assert classify_algorithm(protocol="tls", field="kex", name="X25519") == "classical"
        assert classify_algorithm(protocol="tls", field="kex", name="X25519MLKEM768") == "hybrid_pq"

    def test_tls_signature(self) -> None:
        assert (
            classify_algorithm(protocol="tls", field="signature", name="rsa_pss_rsae_sha256")
            == "classical"
        )
        assert classify_algorithm(protocol="tls", field="signature", name="mldsa65") == "pq_only"

    def test_ssh_hostkey(self) -> None:
        assert (
            classify_algorithm(protocol="ssh", field="hostkey", name="ssh-ed25519") == "classical"
        )

    def test_empty_name(self) -> None:
        assert classify_algorithm(protocol="tls", field="kex", name="") == "unknown"

    def test_bad_field(self) -> None:
        with pytest.raises(ConfigurationError) as exc:
            classify_algorithm(protocol="tls", field="weight", name="x")
        assert exc.value.error_code == "audit.classifier.bad_field"

    def test_bad_protocol(self) -> None:
        with pytest.raises(ConfigurationError):
            classify_algorithm(protocol="quic", field="kex", name="x")


class TestClassify:
    def test_pure_classical_tls(self) -> None:
        finding = classify(
            _probe_ok(
                _tls_target(),
                kex="X25519",
                sig="rsa_pss_rsae_sha256",
                cipher="TLS_AES_128_GCM_SHA256",
            )
        )
        assert finding.category == "classical"
        assert "X25519" in finding.rationale

    def test_hybrid_kex(self) -> None:
        finding = classify(
            _probe_ok(_tls_target(), kex="X25519MLKEM768", sig="rsa_pss_rsae_sha256")
        )
        assert finding.category == "hybrid_pq"

    def test_hybrid_signature(self) -> None:
        finding = classify(_probe_ok(_tls_target(), kex="X25519", sig="ed25519_mldsa65"))
        assert finding.category == "hybrid_pq"

    def test_pq_only_both(self) -> None:
        finding = classify(_probe_ok(_tls_target(), kex="MLKEM768", sig="mldsa65"))
        assert finding.category == "pq_only"

    def test_pq_kex_classical_sig(self) -> None:
        # Asymmetric: one PQ leg = hybrid_pq.
        finding = classify(_probe_ok(_tls_target(), kex="MLKEM768", sig="rsa_pss_rsae_sha256"))
        assert finding.category == "hybrid_pq"

    def test_unknown_kex_propagates(self) -> None:
        finding = classify(_probe_ok(_tls_target(), kex="FrobnicatorEC448", sig="ed25519"))
        assert finding.category == "unknown"
        assert "FrobnicatorEC448" in finding.rationale

    def test_unknown_signature_propagates(self) -> None:
        finding = classify(_probe_ok(_tls_target(), kex="X25519", sig="alien_sig_2099"))
        assert finding.category == "unknown"

    def test_probe_unreachable(self) -> None:
        probe = ProbeResult(
            target=_tls_target(),
            status="unreachable",
            error_detail="connect timeout",
        )
        finding = classify(probe)
        assert finding.category == "unknown"
        assert "unreachable" in finding.rationale

    def test_probe_malformed(self) -> None:
        probe = ProbeResult(
            target=_tls_target(),
            status="malformed",
            error_detail="bad TLS record header",
        )
        finding = classify(probe)
        assert finding.category == "unknown"

    def test_ssh_classical(self) -> None:
        finding = classify(_probe_ok(_ssh_target(), kex="curve25519-sha256", sig="ssh-ed25519"))
        assert finding.category == "classical"

    def test_ssh_hybrid(self) -> None:
        finding = classify(
            _probe_ok(
                _ssh_target(),
                kex="sntrup761x25519-sha512",
                sig="ssh-ed25519",
            )
        )
        assert finding.category == "hybrid_pq"

    def test_pgp_classical_rsa(self) -> None:
        # PgpProbe stuffs the primary key algorithm wire-name into
        # signature_algorithm; the classifier reads it from there.
        finding = classify(_probe_ok(_pgp_target(), sig="rsa_2048"))
        assert finding.category == "classical"

    def test_pgp_classical_ed25519(self) -> None:
        finding = classify(_probe_ok(_pgp_target(), sig="ed25519"))
        assert finding.category == "classical"

    def test_pgp_unknown(self) -> None:
        finding = classify(_probe_ok(_pgp_target(), sig="alien_pgp_algo"))
        assert finding.category == "unknown"

    def test_smime_classical_rsa_chain(self) -> None:
        finding = classify(
            _probe_ok(
                _smime_target(),
                kex="rsa_2048",
                sig="sha256_with_rsa",
            )
        )
        assert finding.category == "classical"

    def test_smime_classical_ed25519_leaf_under_rsa_issuer(self) -> None:
        # Hybrid-of-classicals; both legs are classical → classical.
        finding = classify(
            _probe_ok(
                _smime_target(),
                kex="ed25519",
                sig="sha256_with_rsa",
            )
        )
        assert finding.category == "classical"

    def test_smime_unknown_pubkey(self) -> None:
        finding = classify(
            _probe_ok(
                _smime_target(),
                kex="alien_pubkey",
                sig="sha256_with_rsa",
            )
        )
        assert finding.category == "unknown"

    def test_smime_unknown_sig(self) -> None:
        finding = classify(
            _probe_ok(
                _smime_target(),
                kex="rsa_2048",
                sig="alien_signature",
            )
        )
        assert finding.category == "unknown"


class TestPropertyBasedFailClosed:
    """Hypothesis: any random algorithm string must yield 'unknown' or
    a real category, never raise."""

    @given(st.text())
    def test_classify_tls_kex_total(self, name: str) -> None:
        result = classify_algorithm(protocol="tls", field="kex", name=name)
        assert result in {"classical", "hybrid_pq", "pq_only", "unknown"}

    @given(st.text())
    def test_classify_tls_signature_total(self, name: str) -> None:
        result = classify_algorithm(protocol="tls", field="signature", name=name)
        assert result in {"classical", "hybrid_pq", "pq_only", "unknown"}

    @given(st.text())
    def test_classify_ssh_hostkey_total(self, name: str) -> None:
        result = classify_algorithm(protocol="ssh", field="hostkey", name=name)
        assert result in {"classical", "hybrid_pq", "pq_only", "unknown"}

    @given(
        kex=st.text(min_size=0, max_size=64),
        sig=st.text(min_size=0, max_size=64),
    )
    def test_classify_total(self, kex: str, sig: str) -> None:
        finding = classify(_probe_ok(_tls_target(), kex=kex, sig=sig))
        assert finding.category in {
            "classical",
            "hybrid_pq",
            "pq_only",
            "unknown",
        }
