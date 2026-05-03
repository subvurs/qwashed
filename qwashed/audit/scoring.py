# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""HNDL exposure scoring for Qwashed audit findings.

The score is a deterministic function of:

* The classifier's :class:`Category` (``classical``, ``hybrid_pq``,
  ``pq_only``, ``unknown``).
* The threat profile's :attr:`category_weights` and
  :attr:`archival_likelihood`.

Formula (v0.1)::

    score = category_weight[category] * archival_likelihood

This is deliberately simple: per-category weight is the *baseline*
exposure multiplier, archival_likelihood is the prior on whether the
adversary is recording for later decryption, and the product captures the
"how bad is this in expectation" intuition that policy-driven users want.

Higher-order effects (cipher strength, certificate lifetime, key
length) are deferred to v0.2 -- they're easy to overweight and the
classification already encodes the hardest decision.

The :func:`score_finding` function takes a placeholder-severity finding
from the classifier and returns a new finding with score + severity
populated. The :func:`score_report` function aggregates per-target scores
into the organization-wide rollup.
"""

from __future__ import annotations

from typing import Final

from qwashed.audit.schemas import (
    AuditFinding,
    Severity,
    ThreatProfile,
)
from qwashed.core.errors import ConfigurationError

__all__ = [
    "AGGREGATE_DEFAULT_FOR_NO_FINDINGS",
    "aggregate_score",
    "aggregate_severity",
    "score_finding",
    "severity_for",
]

#: When the auditor is given an empty target list, the aggregate score is
#: by convention 0.0 (no findings = no exposure measured). The CLI is
#: responsible for warning the user that an empty audit is uninformative.
AGGREGATE_DEFAULT_FOR_NO_FINDINGS: Final[float] = 0.0

#: Severity tier order used by :func:`severity_for` and :func:`aggregate_severity`.
_SEVERITY_ORDER: Final[tuple[Severity, ...]] = (
    "info",
    "low",
    "moderate",
    "high",
    "critical",
)


def severity_for(score: float, profile: ThreatProfile) -> Severity:
    """Map a score to a severity bucket using the profile's thresholds.

    The profile's :attr:`severity_thresholds` give the lower edge of each
    bucket. A score of 0.0 always lands in ``info`` (since
    ``severity_thresholds["info"]`` is required to be 0.0 by convention,
    and the schema validator enforces monotonicity).

    A score >= profile.severity_thresholds["critical"] is "critical".
    """
    if not 0.0 <= score <= 1.0:
        raise ConfigurationError(
            f"score must be in [0.0, 1.0], got {score}",
            error_code="audit.scoring.bad_score",
        )
    # Walk thresholds from highest to lowest; first match wins.
    for tier in reversed(_SEVERITY_ORDER):
        cutoff = profile.severity_thresholds[tier]
        if score >= cutoff:
            return tier
    return "info"


def score_finding(
    finding: AuditFinding,
    profile: ThreatProfile,
) -> AuditFinding:
    """Return a copy of ``finding`` with score + severity populated.

    Pure function: does not mutate input. The original ``finding.roadmap``
    is preserved (the roadmap layer fills it in *after* scoring).
    """
    weight = profile.category_weights[finding.category]
    score = weight * profile.archival_likelihood
    # Clamp into [0.0, 1.0] for floating-point safety; both inputs are
    # already bounded in [0.0, 1.0] by schema validators.
    if score < 0.0:
        score = 0.0
    elif score > 1.0:
        score = 1.0
    severity = severity_for(score, profile)
    return finding.model_copy(
        update={
            "score": score,
            "severity": severity,
        }
    )


def aggregate_score(
    findings: list[AuditFinding],
    profile: ThreatProfile,
) -> float:
    """Aggregate per-finding scores into the organization-wide score.

    Uses :attr:`ThreatProfile.aggregation`:

    * ``"max"``: worst-target score (recommended default; one breach
      compromises the org).
    * ``"mean"``: arithmetic mean across all findings (useful for trend
      reporting where you want "average posture").

    Empty input -> :data:`AGGREGATE_DEFAULT_FOR_NO_FINDINGS`.
    """
    if not findings:
        return AGGREGATE_DEFAULT_FOR_NO_FINDINGS
    scores = [f.score for f in findings]
    if profile.aggregation == "max":
        return max(scores)
    if profile.aggregation == "mean":
        return sum(scores) / len(scores)
    # Unreachable due to schema Literal restriction; defensive only.
    raise ConfigurationError(  # pragma: no cover
        f"unknown aggregation strategy {profile.aggregation!r}",
        error_code="audit.scoring.bad_aggregation",
    )


def aggregate_severity(score: float, profile: ThreatProfile) -> Severity:
    """Severity bucket for an aggregate score.

    Identical mapping to :func:`severity_for`; the separate name documents
    intent at the call site (per-finding vs aggregate).
    """
    return severity_for(score, profile)
