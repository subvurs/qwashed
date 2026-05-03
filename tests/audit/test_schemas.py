# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.audit.schemas."""

from __future__ import annotations

import pytest

from qwashed.audit.schemas import (
    AuditFinding,
    AuditReport,
    AuditTarget,
    ProbeResult,
    ThreatProfile,
)
from qwashed.core.errors import SchemaValidationError
from qwashed.core.schemas import parse_strict


def _valid_target() -> AuditTarget:
    return AuditTarget(host="example.com", port=443, protocol="tls")


def _valid_probe(target: AuditTarget) -> ProbeResult:
    return ProbeResult(
        target=target,
        status="ok",
        negotiated_protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256",
        key_exchange_group="X25519",
        signature_algorithm="rsa_pss_rsae_sha256",
        elapsed_seconds=0.012,
    )


class TestAuditTarget:
    def test_basic(self) -> None:
        t = AuditTarget(host="example.com", port=443)
        assert t.host == "example.com"
        assert t.port == 443
        assert t.protocol == "tls"
        assert t.label is None

    def test_strips_whitespace(self) -> None:
        t = AuditTarget(host="  example.com  ", port=443)
        assert t.host == "example.com"

    def test_empty_host_rejected(self) -> None:
        with pytest.raises(Exception):  # pydantic ValidationError
            AuditTarget(host="", port=443)

    def test_port_below_range(self) -> None:
        with pytest.raises(Exception):
            AuditTarget(host="example.com", port=0)

    def test_port_above_range(self) -> None:
        with pytest.raises(Exception):
            AuditTarget(host="example.com", port=65536)

    def test_invalid_protocol(self) -> None:
        with pytest.raises(Exception):
            AuditTarget(host="example.com", port=22, protocol="quic")  # type: ignore[arg-type]

    def test_frozen(self) -> None:
        t = _valid_target()
        with pytest.raises(Exception):
            t.host = "evil.com"


class TestProbeResult:
    def test_ok(self) -> None:
        target = _valid_target()
        probe = _valid_probe(target)
        assert probe.status == "ok"
        assert probe.cipher_suite == "TLS_AES_128_GCM_SHA256"

    def test_unreachable_with_empty_negotiated(self) -> None:
        target = _valid_target()
        probe = ProbeResult(
            target=target,
            status="unreachable",
            error_detail="connect timeout",
        )
        assert probe.status == "unreachable"
        assert probe.cipher_suite == ""
        assert probe.negotiated_protocol_version == ""

    def test_negative_elapsed_rejected(self) -> None:
        target = _valid_target()
        with pytest.raises(Exception):
            ProbeResult(target=target, status="ok", elapsed_seconds=-0.1)

    def test_extras_dict(self) -> None:
        target = _valid_target()
        probe = ProbeResult(
            target=target,
            status="ok",
            extras={"groups_offered": "X25519,X25519MLKEM768"},
        )
        assert "groups_offered" in probe.extras


class TestAuditFinding:
    def test_basic(self) -> None:
        target = _valid_target()
        probe = _valid_probe(target)
        finding = AuditFinding(
            target=target,
            probe=probe,
            category="classical",
            severity="high",
            score=0.71,
            rationale="RSA-PSS for cert signature; HNDL-vulnerable",
        )
        assert finding.score == 0.71
        assert finding.roadmap == []

    def test_score_above_one_rejected(self) -> None:
        target = _valid_target()
        probe = _valid_probe(target)
        with pytest.raises(Exception):
            AuditFinding(
                target=target,
                probe=probe,
                category="classical",
                severity="critical",
                score=1.5,
                rationale="x",
            )

    def test_score_below_zero_rejected(self) -> None:
        target = _valid_target()
        probe = _valid_probe(target)
        with pytest.raises(Exception):
            AuditFinding(
                target=target,
                probe=probe,
                category="classical",
                severity="info",
                score=-0.01,
                rationale="x",
            )


class TestAuditReport:
    def test_basic(self) -> None:
        target = _valid_target()
        probe = _valid_probe(target)
        finding = AuditFinding(
            target=target,
            probe=probe,
            category="hybrid_pq",
            severity="low",
            score=0.18,
            rationale="X25519MLKEM768 hybrid",
        )
        report = AuditReport(
            generated_at="2026-04-30T12:00:00Z",
            profile_name="default",
            findings=[finding],
            aggregate_score=0.18,
            aggregate_severity="low",
            qwashed_version="0.1.0",
        )
        assert report.profile_name == "default"
        assert len(report.findings) == 1

    def test_empty_generated_at_rejected(self) -> None:
        with pytest.raises(Exception):
            AuditReport(
                generated_at="",
                profile_name="default",
                findings=[],
                aggregate_score=0.0,
                aggregate_severity="info",
                qwashed_version="0.1.0",
            )


class TestThreatProfile:
    def _valid_data(self) -> dict:  # type: ignore[type-arg]
        return {
            "name": "test",
            "description": "test profile",
            "category_weights": {
                "classical": 0.85,
                "hybrid_pq": 0.20,
                "pq_only": 0.05,
                "unknown": 0.85,
            },
            "archival_likelihood": 0.65,
            "severity_thresholds": {
                "info": 0.0,
                "low": 0.20,
                "moderate": 0.45,
                "high": 0.65,
                "critical": 0.85,
            },
            "aggregation": "max",
        }

    def test_valid(self) -> None:
        prof = parse_strict(ThreatProfile, self._valid_data())
        assert prof.name == "test"
        assert prof.aggregation == "max"

    def test_missing_category_key(self) -> None:
        data = self._valid_data()
        del data["category_weights"]["pq_only"]
        with pytest.raises(SchemaValidationError):
            parse_strict(ThreatProfile, data)

    def test_extra_category_key(self) -> None:
        data = self._valid_data()
        data["category_weights"]["mystery"] = 0.5
        with pytest.raises(SchemaValidationError):
            parse_strict(ThreatProfile, data)

    def test_weight_out_of_range(self) -> None:
        data = self._valid_data()
        data["category_weights"]["classical"] = 1.5
        with pytest.raises(SchemaValidationError):
            parse_strict(ThreatProfile, data)

    def test_classical_below_hybrid_rejected(self) -> None:
        data = self._valid_data()
        data["category_weights"]["classical"] = 0.10
        data["category_weights"]["hybrid_pq"] = 0.50
        with pytest.raises(SchemaValidationError):
            parse_strict(ThreatProfile, data)

    def test_unknown_below_hybrid_rejected(self) -> None:
        # Fail-closed rule: unknown must >= hybrid_pq.
        data = self._valid_data()
        data["category_weights"]["unknown"] = 0.10
        data["category_weights"]["hybrid_pq"] = 0.50
        with pytest.raises(SchemaValidationError):
            parse_strict(ThreatProfile, data)

    def test_severity_thresholds_non_monotonic(self) -> None:
        data = self._valid_data()
        data["severity_thresholds"]["high"] = 0.30  # below moderate=0.45
        with pytest.raises(SchemaValidationError):
            parse_strict(ThreatProfile, data)

    def test_severity_threshold_out_of_range(self) -> None:
        data = self._valid_data()
        data["severity_thresholds"]["critical"] = 1.5
        with pytest.raises(SchemaValidationError):
            parse_strict(ThreatProfile, data)

    def test_aggregation_invalid(self) -> None:
        data = self._valid_data()
        data["aggregation"] = "median"
        with pytest.raises(SchemaValidationError):
            parse_strict(ThreatProfile, data)

    def test_archival_likelihood_out_of_range(self) -> None:
        data = self._valid_data()
        data["archival_likelihood"] = 1.5
        with pytest.raises(SchemaValidationError):
            parse_strict(ThreatProfile, data)
