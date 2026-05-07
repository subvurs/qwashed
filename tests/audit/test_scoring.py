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
    V02_BOOST_CERT_LIFETIME,
    V02_BOOST_ECC_LT_MIN,
    V02_BOOST_NON_AEAD,
    V02_BOOST_RSA_LT_MIN,
    V02_BOOST_RSA_LT_STRONG,
    V02_MAX_PER_CONTRIBUTION,
    V02_MAX_TOTAL_BOOST,
    aggregate_score,
    aggregate_severity,
    explain_finding,
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


# ---------------------------------------------------------------------------
# §3.5 Richer HNDL scoring (v0.2)
# ---------------------------------------------------------------------------


def _finding_with_probe(
    *,
    category: str = "classical",
    public_key_bits: int | None = None,
    public_key_algorithm_family: str | None = None,
    cert_not_after: str | None = None,
    aead: bool | None = None,
) -> AuditFinding:
    """Build a finding whose probe carries v0.2 fields exercised by the boosts."""
    target = AuditTarget(host="x.example", port=443, protocol="tls")
    probe = ProbeResult(
        target=target,
        status="ok",
        public_key_bits=public_key_bits,
        public_key_algorithm_family=public_key_algorithm_family,
        cert_not_after=cert_not_after,
        aead=aead,
    )
    return AuditFinding(
        target=target,
        probe=probe,
        category=category,  # type: ignore[arg-type]
        severity="info",
        score=0.0,
        rationale="placeholder",
    )


class TestV02Scoring:
    """Per-contribution boosts and the ±0.20 envelope (§3.5)."""

    def test_no_v02_data_no_boost(self) -> None:
        # If the probe carries no v0.2 fields, the v0.2 boosts must be
        # zero; baseline must equal the v0.1 closed-form.
        prof = _profile()
        finding = score_finding(_placeholder_finding("classical"), prof)
        baseline = prof.category_weights["classical"] * prof.archival_likelihood
        assert finding.score == pytest.approx(baseline, abs=1e-9)

    def test_rsa_below_min_boost(self) -> None:
        # RSA-1024 < 2048 -> +V02_BOOST_RSA_LT_MIN (clamped at +0.10).
        prof = _profile()
        baseline = prof.category_weights["classical"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(
                category="classical",
                public_key_bits=1024,
                public_key_algorithm_family="rsa",
            ),
            prof,
        )
        assert finding.score == pytest.approx(
            min(1.0, baseline + V02_BOOST_RSA_LT_MIN), abs=1e-9
        )

    def test_rsa_below_strong_boost(self) -> None:
        # RSA-2048: weak (>=2048 but <3072) -> +V02_BOOST_RSA_LT_STRONG.
        prof = _profile()
        baseline = prof.category_weights["hybrid_pq"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(
                category="hybrid_pq",
                public_key_bits=2048,
                public_key_algorithm_family="rsa",
            ),
            prof,
        )
        assert finding.score == pytest.approx(
            baseline + V02_BOOST_RSA_LT_STRONG, abs=1e-9
        )

    def test_rsa_at_strong_no_boost(self) -> None:
        # RSA-3072 >= strong threshold -> no key-length boost.
        prof = _profile()
        baseline = prof.category_weights["hybrid_pq"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(
                category="hybrid_pq",
                public_key_bits=3072,
                public_key_algorithm_family="rsa",
            ),
            prof,
        )
        assert finding.score == pytest.approx(baseline, abs=1e-9)

    def test_dsa_treated_as_rsa_family(self) -> None:
        # DSA shares the integer-factorization-class threshold ladder.
        prof = _profile()
        baseline = prof.category_weights["classical"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(
                category="classical",
                public_key_bits=1024,
                public_key_algorithm_family="dsa",
            ),
            prof,
        )
        assert finding.score == pytest.approx(
            min(1.0, baseline + V02_BOOST_RSA_LT_MIN), abs=1e-9
        )

    def test_ecc_below_min_boost(self) -> None:
        # ECC-160 < 224 -> +V02_BOOST_ECC_LT_MIN.
        prof = _profile()
        baseline = prof.category_weights["hybrid_pq"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(
                category="hybrid_pq",
                public_key_bits=160,
                public_key_algorithm_family="ec",
            ),
            prof,
        )
        assert finding.score == pytest.approx(
            baseline + V02_BOOST_ECC_LT_MIN, abs=1e-9
        )

    def test_ecc_at_min_no_boost(self) -> None:
        prof = _profile()
        baseline = prof.category_weights["hybrid_pq"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(
                category="hybrid_pq",
                public_key_bits=256,
                public_key_algorithm_family="ec",
            ),
            prof,
        )
        assert finding.score == pytest.approx(baseline, abs=1e-9)

    def test_cert_lifetime_past_horizon_boost(self) -> None:
        # NotAfter past 2030-01-01 horizon -> +V02_BOOST_CERT_LIFETIME.
        prof = _profile()
        baseline = prof.category_weights["hybrid_pq"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(
                category="hybrid_pq",
                cert_not_after="2031-06-15",
            ),
            prof,
        )
        assert finding.score == pytest.approx(
            baseline + V02_BOOST_CERT_LIFETIME, abs=1e-9
        )

    def test_cert_lifetime_inside_horizon_no_boost(self) -> None:
        prof = _profile()
        baseline = prof.category_weights["hybrid_pq"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(
                category="hybrid_pq",
                cert_not_after="2027-01-01",
            ),
            prof,
        )
        assert finding.score == pytest.approx(baseline, abs=1e-9)

    def test_non_aead_boost(self) -> None:
        # aead=False -> +V02_BOOST_NON_AEAD; aead=True or None -> no boost.
        prof = _profile()
        baseline = prof.category_weights["hybrid_pq"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(category="hybrid_pq", aead=False),
            prof,
        )
        assert finding.score == pytest.approx(
            baseline + V02_BOOST_NON_AEAD, abs=1e-9
        )

    def test_aead_true_no_boost(self) -> None:
        prof = _profile()
        baseline = prof.category_weights["hybrid_pq"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(category="hybrid_pq", aead=True),
            prof,
        )
        assert finding.score == pytest.approx(baseline, abs=1e-9)

    def test_total_boost_clamped_at_v02_max(self) -> None:
        # All four contributions stack: RSA<2048 (+0.10) + cert lifetime
        # (+0.05) + non-AEAD (+0.05) = +0.20 exactly; total clamp leaves
        # them as-is. Add ECC family arm separately so we can probe the
        # >0.20 case via the threshold-override test.
        prof = _profile()
        baseline = prof.category_weights["hybrid_pq"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(
                category="hybrid_pq",
                public_key_bits=1024,
                public_key_algorithm_family="rsa",
                cert_not_after="2031-06-15",
                aead=False,
            ),
            prof,
        )
        assert finding.score == pytest.approx(
            baseline + V02_MAX_TOTAL_BOOST, abs=1e-9
        )

    def test_per_contribution_clamp_documented(self) -> None:
        # Sanity: V02_BOOST_RSA_LT_MIN equals V02_MAX_PER_CONTRIBUTION
        # so a single weak-RSA finding cannot exceed the per-arm cap.
        assert V02_BOOST_RSA_LT_MIN <= V02_MAX_PER_CONTRIBUTION

    def test_score_capped_at_one(self) -> None:
        # Even with maximum boost the final score is in [0, 1].
        prof = load_profile("journalism")
        # journalism: classical=1.0 * archival=0.95 = 0.95; +0.20 -> 1.15
        # which must clamp to 1.0.
        finding = score_finding(
            _finding_with_probe(
                category="classical",
                public_key_bits=1024,
                public_key_algorithm_family="rsa",
                cert_not_after="2031-06-15",
                aead=False,
            ),
            prof,
        )
        assert finding.score <= 1.0
        assert finding.score == pytest.approx(1.0, abs=1e-9)

    def test_threshold_override_min_bits(self) -> None:
        # Custom RSA min bumped to 4096 -> a 3072-bit key now triggers
        # the "below strong" boost on a profile with a 3072-strong limit.
        prof_data = load_profile("default").model_dump()
        prof_data["key_length_thresholds"] = {
            "rsa_minimum": 4096,
            "rsa_strong": 8192,
            "ecc_minimum": 224,
        }
        prof = parse_strict(ThreatProfile, prof_data)
        baseline = prof.category_weights["hybrid_pq"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(
                category="hybrid_pq",
                public_key_bits=3072,
                public_key_algorithm_family="rsa",
            ),
            prof,
        )
        # 3072 < 4096 -> below_min boost.
        assert finding.score == pytest.approx(
            min(1.0, baseline + V02_BOOST_RSA_LT_MIN), abs=1e-9
        )

    def test_horizon_override(self) -> None:
        # Custom horizon: pull it back to 2026-01-01 so a 2027 NotAfter
        # is now past horizon.
        prof_data = load_profile("default").model_dump()
        prof_data["cert_lifetime_horizon"] = "2026-01-01"
        prof = parse_strict(ThreatProfile, prof_data)
        baseline = prof.category_weights["hybrid_pq"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(
                category="hybrid_pq",
                cert_not_after="2027-01-01",
            ),
            prof,
        )
        assert finding.score == pytest.approx(
            baseline + V02_BOOST_CERT_LIFETIME, abs=1e-9
        )

    def test_v02_disabled_yields_v01_score(self) -> None:
        # enable_v02_scoring=False -> baseline-only path.
        prof_data = load_profile("default").model_dump()
        prof_data["enable_v02_scoring"] = False
        prof = parse_strict(ThreatProfile, prof_data)
        baseline = prof.category_weights["classical"] * prof.archival_likelihood
        finding = score_finding(
            _finding_with_probe(
                category="classical",
                public_key_bits=1024,
                public_key_algorithm_family="rsa",
                cert_not_after="2031-06-15",
                aead=False,
            ),
            prof,
        )
        assert finding.score == pytest.approx(baseline, abs=1e-9)


class TestV02PropertyEnvelope:
    """Total v0.2 boost is in [0, V02_MAX_TOTAL_BOOST] for any input combination."""

    @given(
        category=st.sampled_from(["classical", "hybrid_pq", "pq_only", "unknown"]),
        rsa_bits=st.one_of(st.none(), st.integers(min_value=512, max_value=8192)),
        ecc_bits=st.one_of(st.none(), st.integers(min_value=128, max_value=521)),
        not_after=st.sampled_from(
            [None, "2024-01-01", "2027-01-01", "2031-06-15", "2099-12-31"]
        ),
        aead=st.one_of(st.none(), st.booleans()),
        family=st.sampled_from(["rsa", "dsa", "ec", "", None]),
    )
    def test_envelope(
        self,
        category: str,
        rsa_bits: int | None,
        ecc_bits: int | None,
        not_after: str | None,
        aead: bool | None,
        family: str | None,
    ) -> None:
        prof = _profile()
        # Pick the bits field according to the family so the test
        # exercises both arms; if family is None we still allow an
        # arbitrary bits value (it must not produce a boost).
        if family in ("rsa", "dsa"):
            bits = rsa_bits
        elif family == "ec":
            bits = ecc_bits
        else:
            bits = rsa_bits
        finding = score_finding(
            _finding_with_probe(
                category=category,
                public_key_bits=bits,
                public_key_algorithm_family=family,
                cert_not_after=not_after,
                aead=aead,
            ),
            prof,
        )
        baseline = (
            prof.category_weights[category]  # type: ignore[index]
            * prof.archival_likelihood
        )
        # Final score = clamp_unit(baseline + boost). Recover boost from
        # the difference and assert it's in the envelope.
        observed_boost = finding.score - baseline
        # Envelope: post-clamp boost is in [-baseline, +V02_MAX_TOTAL_BOOST].
        # The lower edge can dip negative only if baseline+boost > 1 was
        # clamped down to 1 (then observed_boost = 1 - baseline).
        assert observed_boost >= -1e-9 - max(baseline + V02_MAX_TOTAL_BOOST - 1.0, 0.0)
        assert observed_boost <= V02_MAX_TOTAL_BOOST + 1e-9


class TestExplainFinding:
    """`explain_finding` produces a human-readable, deterministic breakdown."""

    def test_baseline_only(self) -> None:
        prof = _profile()
        finding = score_finding(_placeholder_finding("classical"), prof)
        text = explain_finding(finding, prof)
        assert "target=" in text
        assert "category=" in text
        assert "score=" in text
        assert "severity=" in text

    def test_with_boosts_lists_each(self) -> None:
        prof = _profile()
        finding = score_finding(
            _finding_with_probe(
                category="hybrid_pq",
                public_key_bits=1024,
                public_key_algorithm_family="rsa",
                cert_not_after="2031-06-15",
                aead=False,
            ),
            prof,
        )
        text = explain_finding(finding, prof)
        # Each boost arm must be named in the breakdown.
        assert "boost" in text
        assert "rsa" in text.lower() or "key" in text.lower()
        assert "cert" in text.lower() or "lifetime" in text.lower()
        assert "aead" in text.lower()
