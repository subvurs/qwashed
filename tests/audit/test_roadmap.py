# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.audit.roadmap."""

from __future__ import annotations

from qwashed.audit.roadmap import (
    ROADMAP_TABLE,
    attach_roadmap,
    build_roadmap,
)
from qwashed.audit.schemas import AuditFinding, AuditTarget, ProbeResult


def _finding(
    *,
    category: str = "classical",
    severity: str = "high",
    status: str = "ok",
    protocol: str = "tls",
) -> AuditFinding:
    target = AuditTarget(host="x.example", port=443, protocol=protocol)  # type: ignore[arg-type]
    probe = ProbeResult(
        target=target,
        status=status,  # type: ignore[arg-type]
        cipher_suite="TLS_AES_128_GCM_SHA256" if status == "ok" else "",
        key_exchange_group="X25519" if status == "ok" else "",
        signature_algorithm="rsa_pss_rsae_sha256" if status == "ok" else "",
        error_detail="" if status == "ok" else "test error",
    )
    return AuditFinding(
        target=target,
        probe=probe,
        category=category,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        score=0.6,
        rationale="x",
    )


class TestBuildRoadmap:
    def test_classical_tls_high(self) -> None:
        steps = build_roadmap(_finding(category="classical", severity="high"))
        assert any("HIGH PRIORITY" in s for s in steps)
        assert any("X25519MLKEM768" in s for s in steps)

    def test_classical_tls_critical(self) -> None:
        steps = build_roadmap(_finding(category="classical", severity="critical"))
        assert "URGENT" in steps[0]

    def test_hybrid_tls(self) -> None:
        steps = build_roadmap(_finding(category="hybrid_pq", severity="low"))
        assert any("Hybrid PQ key exchange is in place" in s for s in steps)

    def test_pq_only_tls(self) -> None:
        steps = build_roadmap(_finding(category="pq_only", severity="info"))
        assert any("Pure-PQ TLS" in s for s in steps)

    def test_unknown_tls(self) -> None:
        steps = build_roadmap(_finding(category="unknown", severity="high"))
        assert any("could not classify" in s for s in steps)

    def test_classical_ssh(self) -> None:
        steps = build_roadmap(_finding(category="classical", severity="high", protocol="ssh"))
        assert any("SSH" in s or "OpenSSH" in s for s in steps)
        assert any("sntrup761x25519" in s for s in steps)

    def test_unreachable_includes_status_note(self) -> None:
        steps = build_roadmap(
            _finding(category="unknown", severity="moderate", status="unreachable")
        )
        assert any("could not reach" in s for s in steps)

    def test_malformed_includes_status_note(self) -> None:
        steps = build_roadmap(_finding(category="unknown", severity="moderate", status="malformed"))
        assert any("not a valid TLS or SSH" in s for s in steps)

    def test_refused_includes_status_note(self) -> None:
        steps = build_roadmap(_finding(category="unknown", severity="low", status="refused"))
        assert any("actively refused" in s for s in steps)

    def test_severity_note_first(self) -> None:
        # The urgency note must always be the first step.
        # The exact wording differs (critical -> "URGENT", high -> "HIGH PRIORITY",
        # ...) but the note is non-empty and a single sentence.
        expected_keywords = {
            "info": "INFORMATIONAL",
            "low": "LOW",
            "moderate": "MODERATE",
            "high": "HIGH PRIORITY",
            "critical": "URGENT",
        }
        for sev, keyword in expected_keywords.items():
            steps = build_roadmap(_finding(severity=sev))
            assert steps[0].startswith(keyword), (sev, steps[0])

    def test_deterministic(self) -> None:
        finding = _finding()
        assert build_roadmap(finding) == build_roadmap(finding)


class TestAttachRoadmap:
    def test_populates_roadmap_field(self) -> None:
        finding = _finding()
        result = attach_roadmap(finding)
        assert result.roadmap == build_roadmap(finding)
        # Original is unchanged.
        assert finding.roadmap == []


class TestRoadmapTable:
    def test_complete_coverage(self) -> None:
        # Every (protocol, category) combination must have a baseline.
        keys = {key for key, _ in ROADMAP_TABLE}
        expected = {("tls", c) for c in ("classical", "hybrid_pq", "pq_only", "unknown")} | {
            ("ssh", c) for c in ("classical", "hybrid_pq", "pq_only", "unknown")
        }
        assert expected.issubset(keys)
