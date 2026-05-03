# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.audit.pipeline."""

from __future__ import annotations

from qwashed.audit.pipeline import audit_target, run_audit
from qwashed.audit.probe import StaticProbe
from qwashed.audit.profile_loader import load_profile
from qwashed.audit.schemas import AuditTarget, ProbeResult


def _canned(host: str, port: int, **fields: str) -> ProbeResult:
    target = AuditTarget(host=host, port=port)
    return ProbeResult(target=target, status="ok", **fields)  # type: ignore[arg-type]


class TestAuditTarget:
    def test_classical_finding(self) -> None:
        canned = _canned(
            "x.example",
            443,
            negotiated_protocol_version="TLSv1.3",
            cipher_suite="TLS_AES_128_GCM_SHA256",
            key_exchange_group="X25519",
            signature_algorithm="rsa_pss_rsae_sha256",
        )
        probe = StaticProbe({("x.example", 443): canned})
        target = AuditTarget(host="x.example", port=443)
        finding = audit_target(
            target,
            probe_impl=probe,
            profile=load_profile("default"),
        )
        assert finding.category == "classical"
        assert finding.severity in {"info", "low", "moderate", "high", "critical"}
        assert finding.score > 0
        assert finding.roadmap, "roadmap must be populated"
        assert finding.roadmap[0].startswith(
            ("URGENT", "HIGH PRIORITY", "MODERATE", "LOW", "INFORMATIONAL")
        )

    def test_hybrid_finding(self) -> None:
        canned = _canned(
            "x.example",
            443,
            negotiated_protocol_version="TLSv1.3",
            cipher_suite="TLS_AES_128_GCM_SHA256",
            key_exchange_group="X25519MLKEM768",
            signature_algorithm="ed25519",
        )
        probe = StaticProbe({("x.example", 443): canned})
        target = AuditTarget(host="x.example", port=443)
        finding = audit_target(
            target,
            probe_impl=probe,
            profile=load_profile("default"),
        )
        assert finding.category == "hybrid_pq"

    def test_unreachable_finding(self) -> None:
        # No canned result -> StaticProbe returns "unreachable"; classifier
        # propagates as "unknown" (fail-closed).
        probe = StaticProbe({})
        target = AuditTarget(host="x.example", port=443)
        finding = audit_target(
            target,
            probe_impl=probe,
            profile=load_profile("default"),
        )
        assert finding.category == "unknown"
        assert finding.probe.status == "unreachable"


class TestRunAudit:
    def test_empty_targets(self) -> None:
        report = run_audit(
            [],
            profile=load_profile("default"),
            probe_impl=StaticProbe({}),
            generated_at="2026-01-01T00:00:00Z",
            qwashed_version="0.1.0",
        )
        assert report.findings == []
        assert report.aggregate_score == 0.0
        assert report.aggregate_severity == "info"

    def test_two_targets_max(self) -> None:
        canned1 = _canned(
            "a.example",
            443,
            negotiated_protocol_version="TLSv1.3",
            cipher_suite="TLS_AES_128_GCM_SHA256",
            key_exchange_group="X25519",
            signature_algorithm="rsa_pss_rsae_sha256",
        )
        canned2 = _canned(
            "b.example",
            443,
            negotiated_protocol_version="TLSv1.3",
            cipher_suite="TLS_AES_128_GCM_SHA256",
            key_exchange_group="X25519MLKEM768",
            signature_algorithm="ed25519",
        )
        probe = StaticProbe(
            {
                ("a.example", 443): canned1,
                ("b.example", 443): canned2,
            }
        )
        report = run_audit(
            [
                AuditTarget(host="a.example", port=443),
                AuditTarget(host="b.example", port=443),
            ],
            profile=load_profile("default"),
            probe_impl=probe,
            generated_at="2026-01-01T00:00:00Z",
            qwashed_version="0.1.0",
        )
        assert len(report.findings) == 2
        # default profile uses max aggregation: classical dominates.
        assert report.findings[0].category == "classical"
        assert report.findings[1].category == "hybrid_pq"
        assert report.aggregate_score == report.findings[0].score

    def test_deterministic(self) -> None:
        canned = _canned(
            "x.example",
            443,
            key_exchange_group="X25519",
            signature_algorithm="rsa_pss_rsae_sha256",
        )
        probe = StaticProbe({("x.example", 443): canned})
        target = AuditTarget(host="x.example", port=443)
        kwargs = {
            "profile": load_profile("default"),
            "probe_impl": probe,
            "generated_at": "2026-01-01T00:00:00Z",
            "qwashed_version": "0.1.0",
        }
        r1 = run_audit([target], **kwargs)  # type: ignore[arg-type]
        r2 = run_audit([target], **kwargs)  # type: ignore[arg-type]
        assert r1.model_dump() == r2.model_dump()
