# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""End-to-end audit pipeline.

Wires the per-target stages (probe -> classify -> roadmap -> score) into
a single function and rolls per-target findings into an
:class:`AuditReport`. Imported by :mod:`qwashed.audit.cli`; also useful
as a programmatic entry point for tests and embedders.

The pipeline does no I/O beyond what the supplied probe implementation
does. It does not load profiles, write files, or sign anything; the CLI
is responsible for those steps.

Determinism
-----------
Pure function over (targets, probe_impl, profile, generated_at, version):
identical inputs always produce identical :class:`AuditReport` output
modulo the probe layer. Tests pass a :class:`StaticProbe` to remove the
remaining nondeterminism.
"""

from __future__ import annotations

from collections.abc import Iterable

from qwashed.audit.classifier import classify, load_algorithm_tables
from qwashed.audit.probe import Probe, StdlibTlsProbe
from qwashed.audit.roadmap import attach_roadmap
from qwashed.audit.schemas import (
    AuditFinding,
    AuditReport,
    AuditTarget,
    ThreatProfile,
)
from qwashed.audit.scoring import (
    aggregate_score,
    aggregate_severity,
    score_finding,
)

__all__ = ["audit_target", "run_audit"]


def audit_target(
    target: AuditTarget,
    *,
    probe_impl: Probe,
    profile: ThreatProfile,
) -> AuditFinding:
    """Run the full per-target pipeline.

    Steps: probe -> classify -> score (with profile) -> attach roadmap.
    The roadmap is attached after scoring so the urgency note matches
    the final severity.
    """
    probe_result = probe_impl.probe(target)
    finding = classify(probe_result, tables=load_algorithm_tables())
    finding = score_finding(finding, profile)
    finding = attach_roadmap(finding)
    return finding


def run_audit(
    targets: Iterable[AuditTarget],
    *,
    profile: ThreatProfile,
    probe_impl: Probe | None = None,
    generated_at: str,
    qwashed_version: str,
) -> AuditReport:
    """Run the audit over ``targets`` and roll up into an :class:`AuditReport`.

    Parameters
    ----------
    targets:
        Iterable of targets, in the order the report should list them.
    profile:
        Loaded threat profile that drives scoring + severity thresholds.
    probe_impl:
        Probe to use; defaults to :class:`StdlibTlsProbe`. Tests pass a
        :class:`StaticProbe` for determinism.
    generated_at:
        ISO 8601 UTC timestamp string. The CLI freezes this under
        ``--deterministic``.
    qwashed_version:
        Version string to embed in the report (passed in so callers
        decide whether to use ``__version__`` or a frozen constant for
        deterministic output).
    """
    impl = probe_impl if probe_impl is not None else StdlibTlsProbe()
    findings: list[AuditFinding] = []
    for target in targets:
        findings.append(audit_target(target, probe_impl=impl, profile=profile))

    score = aggregate_score(findings, profile)
    severity = aggregate_severity(score, profile)
    return AuditReport(
        generated_at=generated_at,
        profile_name=profile.name,
        findings=findings,
        aggregate_score=score,
        aggregate_severity=severity,
        qwashed_version=qwashed_version,
    )
