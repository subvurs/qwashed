# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.audit.scoring."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from qwashed.audit.profile_loader import load_profile
from qwashed.audit.schemas import (
    AuditFinding,
    AuditTarget,
    ProbeResult,
    ThreatProfile,
)
from qwashed.audit.scoring import (
    aggregate_score,
    aggregate_severity,
    score_finding,
    severity_for,
)
from qwashed.core.errors import ConfigurationError
from qwashed.core.schemas import parse_strict


def _profile() -> ThreatProfile:
    return load_profile("default")


def _placeholder_finding(category: str = "classical") -> AuditFinding:
    target = AuditTarget(host="x.example", port=443, protocol="tls")
    probe = ProbeResult(target=target, status="ok")
    return AuditFinding(
        target=target,
        probe=probe,
        category=category,  # type: ignore[arg-type]
        severity="info",
        score=0.0,
        rationale="placeholder",
    )


class TestSeverityFor:
    def test_info_at_zero(self) -> None:
        assert severity_for(0.0, _profile()) == "info"

    def test_low_at_threshold(self) -> None:
        prof = _profile()
        assert severity_for(prof.severity_thresholds["low"], prof) == "low"

    def test_critical_at_threshold(self) -> None:
        prof = _profile()
        assert severity_for(prof.severity_thresholds["critical"], prof) == "critical"

    def test_critical_at_one(self) -> None:
        assert severity_for(1.0, _profile()) == "critical"

    def test_just_below_critical(self) -> None:
        prof = _profile()
        eps = 1e-9
        assert severity_for(prof.severity_thresholds["critical"] - eps, prof) == "high"

    def test_score_below_zero_rejected(self) -> None:
        with pytest.raises(ConfigurationError):
            severity_for(-0.01, _profile())

    def test_score_above_one_rejected(self) -> None:
        with pytest.raises(ConfigurationError):
            severity_for(1.01, _profile())


class TestScoreFinding:
    def test_classical_default_profile(self) -> None:
        prof = _profile()
        finding = score_finding(_placeholder_finding("classical"), prof)
        # default profile: classical=0.85, archival=0.65 -> 0.5525
        assert finding.score == pytest.approx(0.85 * 0.65, abs=1e-9)

    def test_hybrid_default_profile(self) -> None:
        prof = _profile()
        finding = score_finding(_placeholder_finding("hybrid_pq"), prof)
        assert finding.score == pytest.approx(0.20 * 0.65, abs=1e-9)

    def test_pq_only_default(self) -> None:
        prof = _profile()
        finding = score_finding(_placeholder_finding("pq_only"), prof)
        assert finding.score == pytest.approx(0.05 * 0.65, abs=1e-9)

    def test_unknown_at_classical_weight(self) -> None:
        # Fail-closed: unknown weight equals classical weight in default.
        prof = _profile()
        unknown = score_finding(_placeholder_finding("unknown"), prof)
        classical = score_finding(_placeholder_finding("classical"), prof)
        assert unknown.score == pytest.approx(classical.score, abs=1e-9)

    def test_severity_populated(self) -> None:
        prof = _profile()
        finding = score_finding(_placeholder_finding("classical"), prof)
        # default profile: 0.5525 falls in [moderate=0.45, high=0.65)
        assert finding.severity == "moderate"

    def test_journalism_classical_critical(self) -> None:
        prof = load_profile("journalism")
        finding = score_finding(_placeholder_finding("classical"), prof)
        # journalism: classical=1.0 * archival=0.95 = 0.95 -> critical
        assert finding.severity == "critical"

    def test_does_not_mutate_input(self) -> None:
        prof = _profile()
        original = _placeholder_finding("classical")
        score_finding(original, prof)
        assert original.score == 0.0
        assert original.severity == "info"

    def test_preserves_roadmap(self) -> None:
        prof = _profile()
        target = AuditTarget(host="x.example", port=443, protocol="tls")
        probe = ProbeResult(target=target, status="ok")
        original = AuditFinding(
            target=target,
            probe=probe,
            category="classical",
            severity="info",
            score=0.0,
            rationale="x",
            roadmap=["step one", "step two"],
        )
        scored = score_finding(original, prof)
        assert scored.roadmap == ["step one", "step two"]


class TestAggregateScore:
    def test_empty(self) -> None:
        assert aggregate_score([], _profile()) == 0.0

    def test_max(self) -> None:
        prof = _profile()
        f1 = score_finding(_placeholder_finding("hybrid_pq"), prof)
        f2 = score_finding(_placeholder_finding("classical"), prof)
        f3 = score_finding(_placeholder_finding("pq_only"), prof)
        assert aggregate_score([f1, f2, f3], prof) == pytest.approx(f2.score)

    def test_mean(self) -> None:
        prof_data = _profile().model_dump()
        prof_data["aggregation"] = "mean"
        prof = parse_strict(ThreatProfile, prof_data)
        f1 = score_finding(_placeholder_finding("hybrid_pq"), prof)
        f2 = score_finding(_placeholder_finding("classical"), prof)
        expected = (f1.score + f2.score) / 2
        assert aggregate_score([f1, f2], prof) == pytest.approx(expected)


class TestAggregateSeverity:
    def test_passthrough(self) -> None:
        # Aggregate severity uses the same threshold map as severity_for.
        prof = _profile()
        assert aggregate_severity(0.5, prof) == severity_for(0.5, prof)


class TestPropertyMonotonic:
    """Score is monotonic in archival_likelihood (for fixed category)."""

    @given(
        archival_a=st.floats(min_value=0.0, max_value=1.0),
        archival_b=st.floats(min_value=0.0, max_value=1.0),
    )
    def test_monotonic_archival(self, archival_a: float, archival_b: float) -> None:
        prof_data = load_profile("default").model_dump()

        prof_data["archival_likelihood"] = archival_a
        prof_a = parse_strict(ThreatProfile, prof_data)

        prof_data["archival_likelihood"] = archival_b
        prof_b = parse_strict(ThreatProfile, prof_data)

        finding = _placeholder_finding("classical")
        score_a = score_finding(finding, prof_a).score
        score_b = score_finding(finding, prof_b).score
        # The relation must agree with the relation between archivals.
        if archival_a < archival_b:
            assert score_a <= score_b
        elif archival_a > archival_b:
            assert score_a >= score_b
        else:
            assert score_a == pytest.approx(score_b)

    @given(score=st.floats(min_value=0.0, max_value=1.0))
    def test_severity_total(self, score: float) -> None:
        prof = _profile()
        result = severity_for(score, prof)
        assert result in {"info", "low", "moderate", "high", "critical"}
