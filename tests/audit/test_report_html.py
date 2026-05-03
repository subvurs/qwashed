# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.audit.report_html."""

from __future__ import annotations

from qwashed.audit.report_html import render_audit_html
from qwashed.audit.schemas import (
    AuditFinding,
    AuditReport,
    AuditTarget,
    ProbeResult,
)


def _build_report(
    *,
    finding_label: str | None = None,
    rationale: str = "TLS kex='X25519' (classical) -> classical",
) -> AuditReport:
    target = AuditTarget(host="example.org", port=443, label=finding_label)
    probe = ProbeResult(
        target=target,
        status="ok",
        negotiated_protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256",
        key_exchange_group="X25519",
        signature_algorithm="rsa_pss_rsae_sha256",
    )
    finding = AuditFinding(
        target=target,
        probe=probe,
        category="classical",
        severity="high",
        score=0.5525,
        rationale=rationale,
        roadmap=[
            "HIGH PRIORITY: schedule remediation within the current operational quarter.",
            "Enable hybrid post-quantum TLS key exchange on the server.",
        ],
    )
    return AuditReport(
        generated_at="2026-01-01T00:00:00Z",
        profile_name="default",
        findings=[finding],
        aggregate_score=0.5525,
        aggregate_severity="high",
        qwashed_version="0.1.0",
    )


class TestRenderAuditHtml:
    def test_produces_html_document(self) -> None:
        html = render_audit_html(_build_report())
        assert html.startswith("<!DOCTYPE html>")
        assert "Qwashed audit report" in html
        assert "example.org:443" in html
        assert "high" in html
        assert "X25519" in html

    def test_finding_with_label(self) -> None:
        html = render_audit_html(_build_report(finding_label="prod-mta"))
        assert "[prod-mta]" in html

    def test_xss_in_rationale_escaped(self) -> None:
        # Rationale flows through escape_html; <script> must not appear raw.
        evil = "<script>alert('x')</script>"
        html = render_audit_html(_build_report(rationale=evil))
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_includes_pubkey_fingerprint(self) -> None:
        html = render_audit_html(
            _build_report(),
            pubkey_fingerprint="abcd1234abcd1234extra",
        )
        assert "abcd1234abcd1234" in html

    def test_unsigned_footer(self) -> None:
        html = render_audit_html(_build_report())
        assert "Unsigned report" in html

    def test_empty_findings(self) -> None:
        report = AuditReport(
            generated_at="2026-01-01T00:00:00Z",
            profile_name="default",
            findings=[],
            aggregate_score=0.0,
            aggregate_severity="info",
            qwashed_version="0.1.0",
        )
        html = render_audit_html(report)
        assert "No targets supplied" in html

    def test_findings_sorted_by_score_desc(self) -> None:
        target_a = AuditTarget(host="lo.example", port=443)
        target_b = AuditTarget(host="hi.example", port=443)
        probe_a = ProbeResult(target=target_a, status="ok")
        probe_b = ProbeResult(target=target_b, status="ok")
        finding_low = AuditFinding(
            target=target_a,
            probe=probe_a,
            category="hybrid_pq",
            severity="low",
            score=0.1,
            rationale="lo",
            roadmap=["LOW: ok"],
        )
        finding_high = AuditFinding(
            target=target_b,
            probe=probe_b,
            category="classical",
            severity="critical",
            score=0.9,
            rationale="hi",
            roadmap=["URGENT: critical"],
        )
        report = AuditReport(
            generated_at="2026-01-01T00:00:00Z",
            profile_name="default",
            findings=[finding_low, finding_high],
            aggregate_score=0.9,
            aggregate_severity="critical",
            qwashed_version="0.1.0",
        )
        html = render_audit_html(report)
        # The high-score target should appear first in the body.
        assert html.find("hi.example") < html.find("lo.example")
