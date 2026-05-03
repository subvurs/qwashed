# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""HTML rendering for Qwashed audit reports.

Produces a single self-contained HTML document with no external assets,
so the file can be emailed, archived, or read offline. Uses
:mod:`qwashed.core.report` for placeholder substitution: every dynamic
value flows through HTML escaping unless explicitly marked safe.

Layout
------
* Header: profile name, generated_at, qwashed_version, aggregate score +
  severity.
* Findings: one ``<section>`` per :class:`AuditFinding`, sorted by score
  descending so the most-exposed targets appear first.
* Per-finding details: target, probe status, classification rationale,
  roadmap steps.
* Footer: signature footprint (first 16 chars of the Ed25519 pubkey
  fingerprint) so the reader can verify the artifact was not edited
  after signing.

The HTML is intentionally plain (no JavaScript, no remote fonts, no
images). Civil-society readers may open it on locked-down devices or
inside email clients with stripped CSS.
"""

from __future__ import annotations

from typing import Final

from qwashed.audit.schemas import AuditFinding, AuditReport
from qwashed.core.report import escape_html, mark_safe, render_html

__all__ = ["render_audit_html"]


_SEVERITY_COLORS: Final[dict[str, str]] = {
    "critical": "#a00000",
    "high": "#c04400",
    "moderate": "#a07000",
    "low": "#306030",
    "info": "#404060",
}


_TEMPLATE: Final[str] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{{ title }}</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       margin: 2rem auto; max-width: 60rem; color: #222; line-height: 1.45; }
h1, h2, h3 { color: #111; }
.header { border-bottom: 1px solid #ccc; padding-bottom: 1rem; margin-bottom: 1rem; }
.severity { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 0.25rem;
            color: white; font-weight: bold; font-size: 0.9rem; }
.finding { border: 1px solid #ddd; padding: 1rem; margin: 1rem 0;
           border-radius: 0.25rem; background: #fafafa; }
.field { margin: 0.25rem 0; }
.field-label { color: #555; font-weight: bold; }
.rationale { font-family: ui-monospace, "SF Mono", monospace; font-size: 0.85rem;
             white-space: pre-wrap; word-break: break-word;
             background: #f0f0f0; padding: 0.5rem; border-radius: 0.25rem; }
.roadmap-list { margin: 0.5rem 0 0 1.5rem; padding: 0; }
.roadmap-list li { margin: 0.25rem 0; }
.footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #ccc;
          color: #555; font-size: 0.85rem; }
.aggregate { font-size: 1.1rem; }
.score { font-family: ui-monospace, "SF Mono", monospace; }
</style>
</head>
<body>
<div class="header">
<h1>Qwashed audit report</h1>
<div class="field"><span class="field-label">Profile:</span> {{ profile_name }}</div>
<div class="field"><span class="field-label">Generated:</span> {{ generated_at }}</div>
<div class="field"><span class="field-label">Qwashed version:</span> {{ qwashed_version }}</div>
<div class="field aggregate">
<span class="field-label">Aggregate severity:</span>
<span class="severity" style="background: {{ aggregate_color }};">{{ aggregate_severity }}</span>
&nbsp;<span class="score">(score = {{ aggregate_score }})</span>
</div>
<div class="field"><span class="field-label">Findings:</span> {{ findings_count }}</div>
</div>

<h2>Findings</h2>
{{ findings_html }}

<div class="footer">
<p>{{ footer_note }}</p>
<p>Verify with: <code>qwashed verify &lt;artifact.json&gt;</code></p>
</div>
</body>
</html>
"""


_FINDING_TEMPLATE: Final[str] = """<section class="finding">
<h3>{{ heading }}</h3>
<div class="field"><span class="field-label">Severity:</span>
<span class="severity" style="background: {{ severity_color }};">{{ severity }}</span>
&nbsp;<span class="score">(score = {{ score }})</span></div>
<div class="field"><span class="field-label">Category:</span> {{ category }}</div>
<div class="field"><span class="field-label">Probe status:</span> {{ probe_status }}</div>
<div class="field"><span class="field-label">Negotiated:</span> {{ negotiated }}</div>
<div class="field"><span class="field-label">Rationale:</span></div>
<div class="rationale">{{ rationale }}</div>
<div class="field"><span class="field-label">Migration roadmap:</span></div>
<ol class="roadmap-list">{{ roadmap_items_html }}</ol>
</section>
"""


def _render_finding(finding: AuditFinding) -> str:
    target = finding.target
    label = f" [{target.label}]" if target.label else ""
    heading = f"{target.protocol.upper()} {target.host}:{target.port}{label}"
    probe = finding.probe
    if probe.status == "ok":
        negotiated = (
            f"version={probe.negotiated_protocol_version or '-'}; "
            f"cipher={probe.cipher_suite or '-'}; "
            f"kex={probe.key_exchange_group or '-'}; "
            f"sig={probe.signature_algorithm or '-'}"
        )
    else:
        negotiated = f"(probe did not complete: {probe.status})"

    items_html = "".join(f"<li>{escape_html(step)}</li>" for step in finding.roadmap)
    if not items_html:
        items_html = "<li>(no roadmap steps; unexpected)</li>"

    color = _SEVERITY_COLORS.get(finding.severity, "#444")
    return render_html(
        _FINDING_TEMPLATE,
        {
            "heading": heading,
            "severity": finding.severity,
            "severity_color": color,
            "score": f"{finding.score:.4f}",
            "category": finding.category,
            "probe_status": probe.status,
            "negotiated": negotiated,
            "rationale": finding.rationale,
            "roadmap_items_html": mark_safe(items_html),
        },
    )


def render_audit_html(
    report: AuditReport,
    *,
    pubkey_fingerprint: str = "",
) -> str:
    """Render ``report`` as a self-contained HTML document.

    Parameters
    ----------
    report:
        Fully-populated audit report (post-signing or pre-signing).
    pubkey_fingerprint:
        Optional first-N characters of the Ed25519 pubkey base64 used to
        sign the artifact. Displayed in the footer so a reader can
        cross-check before trusting the document. Empty string if the
        report is unsigned.
    """
    findings = sorted(report.findings, key=lambda f: f.score, reverse=True)
    findings_html = "".join(_render_finding(f) for f in findings)
    if not findings_html:
        findings_html = (
            "<p><em>No targets supplied. An empty audit cannot detect "
            "exposure; supply at least one target in the audit "
            "configuration.</em></p>"
        )

    aggregate_color = _SEVERITY_COLORS.get(report.aggregate_severity, "#444")
    if pubkey_fingerprint:
        footer_note = f"Signed by Ed25519 public key fingerprint {pubkey_fingerprint[:16]}\u2026"
    else:
        footer_note = "Unsigned report (no signing key was provided)."

    return render_html(
        _TEMPLATE,
        {
            "title": f"Qwashed audit \u2013 {report.profile_name}",
            "profile_name": report.profile_name,
            "generated_at": report.generated_at,
            "qwashed_version": report.qwashed_version,
            "aggregate_severity": report.aggregate_severity,
            "aggregate_color": aggregate_color,
            "aggregate_score": f"{report.aggregate_score:.4f}",
            "findings_count": str(len(report.findings)),
            "findings_html": mark_safe(findings_html),
            "footer_note": footer_note,
        },
    )
