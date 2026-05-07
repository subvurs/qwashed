# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""HNDL exposure scoring for Qwashed audit findings.

The score is a deterministic function of:

* The classifier's :class:`Category` (``classical``, ``hybrid_pq``,
  ``pq_only``, ``unknown``).
* The threat profile's :attr:`category_weights` and
  :attr:`archival_likelihood`.
* Optionally (v0.2, §3.5) per-finding boosts derived from key length,
  certificate lifetime, and AEAD status. Gated by
  :attr:`ThreatProfile.enable_v02_scoring`.

Formula (v0.1)::

    score = category_weight[category] * archival_likelihood

Formula (v0.2, when ``enable_v02_scoring`` is True)::

    score = clamp(
        category_weight[category] * archival_likelihood
        + sum(boosts),
        0.0, 1.0,
    )

where each individual boost is at most ``V02_MAX_PER_CONTRIBUTION``
(0.10) and the sum of boosts is clamped to ``V02_MAX_TOTAL_BOOST``
(0.20). The clamp is applied *after* the baseline so that a profile
which already saturates classical at 1.0 cannot somehow exceed 1.0.

Boost catalogue (v0.2)
----------------------

* ``+0.10`` -- RSA modulus / DSA bit length below ``rsa_minimum``
  (default 2048). This is the headline "obviously broken in 2026"
  case.
* ``+0.05`` -- RSA / DSA bit length below ``rsa_strong`` (default
  3072) but >= ``rsa_minimum``. Captures the "still standardized
  but undersized for HNDL adversaries" tier.
* ``+0.05`` -- EC curve bit length below ``ecc_minimum`` (default
  224). NIST P-192 is the obvious target.
* ``+0.05`` -- TLS / S/MIME leaf cert NotAfter strictly later than
  ``cert_lifetime_horizon`` (default ``"2030-01-01"``). Long-lived
  certs widen the harvest window.
* ``+0.05`` -- TLS cipher is not AEAD (TLS 1.2 CBC suites). Pure
  classical hygiene contribution; AEAD failure is independent of
  HNDL but still raises baseline exposure.

The :func:`score_finding` function takes a placeholder-severity finding
from the classifier and returns a new finding with score + severity
populated. The :func:`score_report` function aggregates per-target scores
into the organization-wide rollup. :func:`explain_finding` returns a
human-readable breakdown for the ``--explain`` CLI flag.
"""

from __future__ import annotations

from typing import Final

from qwashed.audit.schemas import (
    AuditFinding,
    ProbeResult,
    Severity,
    ThreatProfile,
)
from qwashed.core.errors import ConfigurationError

__all__ = [
    "AGGREGATE_DEFAULT_FOR_NO_FINDINGS",
    "DEFAULT_CERT_LIFETIME_HORIZON",
    "DEFAULT_ECC_MIN_BITS",
    "DEFAULT_RSA_MIN_BITS",
    "DEFAULT_RSA_STRONG_BITS",
    "V02_BOOST_CERT_LIFETIME",
    "V02_BOOST_ECC_LT_MIN",
    "V02_BOOST_NON_AEAD",
    "V02_BOOST_RSA_LT_MIN",
    "V02_BOOST_RSA_LT_STRONG",
    "V02_MAX_PER_CONTRIBUTION",
    "V02_MAX_TOTAL_BOOST",
    "aggregate_score",
    "aggregate_severity",
    "explain_finding",
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

# --- v0.2 (§3.5) scoring constants ----------------------------------------

#: Max per-contribution boost. No individual boost may push the score
#: more than this much; the table above is consistent with this bound.
V02_MAX_PER_CONTRIBUTION: Final[float] = 0.10

#: Max total boost from all v0.2 contributions combined. If raw boosts
#: would exceed this, they are scaled proportionally and the rationale
#: notes ``[clamped]``.
V02_MAX_TOTAL_BOOST: Final[float] = 0.20

#: Boost applied when an RSA / DSA public key is below ``rsa_minimum``.
V02_BOOST_RSA_LT_MIN: Final[float] = 0.10

#: Boost applied when RSA / DSA bit length is in
#: ``[rsa_minimum, rsa_strong)``.
V02_BOOST_RSA_LT_STRONG: Final[float] = 0.05

#: Boost applied when an EC public key is below ``ecc_minimum``.
V02_BOOST_ECC_LT_MIN: Final[float] = 0.05

#: Boost applied when leaf cert NotAfter > ``cert_lifetime_horizon``.
V02_BOOST_CERT_LIFETIME: Final[float] = 0.05

#: Boost applied when the negotiated TLS cipher is non-AEAD.
V02_BOOST_NON_AEAD: Final[float] = 0.05

#: Default RSA / DSA minimum bit length. Below this -> +0.10.
DEFAULT_RSA_MIN_BITS: Final[int] = 2048

#: Default RSA / DSA "strong" bit length. ``[2048, 3072)`` -> +0.05.
DEFAULT_RSA_STRONG_BITS: Final[int] = 3072

#: Default EC minimum bit length. Below this -> +0.05.
DEFAULT_ECC_MIN_BITS: Final[int] = 224

#: Default cert-lifetime horizon (ISO 8601 ``YYYY-MM-DD``). Cert NotAfter
#: strictly greater than this date adds +0.05.
DEFAULT_CERT_LIFETIME_HORIZON: Final[str] = "2030-01-01"


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


def _resolve_key_length_thresholds(
    profile: ThreatProfile,
) -> tuple[int, int, int]:
    """Return (rsa_minimum, rsa_strong, ecc_minimum) honouring overrides."""
    overrides = profile.key_length_thresholds or {}
    rsa_min = int(overrides.get("rsa_minimum", DEFAULT_RSA_MIN_BITS))
    rsa_strong = int(overrides.get("rsa_strong", DEFAULT_RSA_STRONG_BITS))
    ecc_min = int(overrides.get("ecc_minimum", DEFAULT_ECC_MIN_BITS))
    if rsa_strong < rsa_min:
        raise ConfigurationError(
            f"key_length_thresholds.rsa_strong ({rsa_strong}) must be >= "
            f"rsa_minimum ({rsa_min})",
            error_code="audit.scoring.bad_thresholds",
        )
    if rsa_min <= 0 or rsa_strong <= 0 or ecc_min <= 0:
        raise ConfigurationError(
            "key_length_thresholds entries must be positive integers",
            error_code="audit.scoring.bad_thresholds",
        )
    return rsa_min, rsa_strong, ecc_min


def _resolve_cert_horizon(profile: ThreatProfile) -> str:
    horizon = profile.cert_lifetime_horizon or DEFAULT_CERT_LIFETIME_HORIZON
    # Cheap shape check -- full datetime parsing is the caller's concern.
    if len(horizon) < 10 or horizon[4] != "-" or horizon[7] != "-":
        raise ConfigurationError(
            f"cert_lifetime_horizon must look like 'YYYY-MM-DD', got "
            f"{horizon!r}",
            error_code="audit.scoring.bad_horizon",
        )
    return horizon


def _compute_v02_boosts(
    probe: ProbeResult,
    profile: ThreatProfile,
) -> list[tuple[str, float, str]]:
    """Compute the list of v0.2 boost contributions.

    Returns a list of ``(name, delta, rationale)`` triples where ``delta``
    is the unsigned positive contribution before clamping. The caller is
    responsible for total clamping and final rationale formatting.

    Each individual contribution is bounded by
    :data:`V02_MAX_PER_CONTRIBUTION` (0.10).
    """
    boosts: list[tuple[str, float, str]] = []

    # --- key length boost ---
    family = (probe.public_key_algorithm_family or "").lower()
    bits = probe.public_key_bits
    if bits is not None and bits > 0:
        if family in {"rsa", "dsa"}:
            rsa_min, rsa_strong, _ = _resolve_key_length_thresholds(profile)
            if bits < rsa_min:
                boosts.append(
                    (
                        "key_length",
                        V02_BOOST_RSA_LT_MIN,
                        f"{family.upper()}-{bits} below "
                        f"rsa_minimum ({rsa_min})",
                    )
                )
            elif bits < rsa_strong:
                boosts.append(
                    (
                        "key_length",
                        V02_BOOST_RSA_LT_STRONG,
                        f"{family.upper()}-{bits} below "
                        f"rsa_strong ({rsa_strong})",
                    )
                )
        elif family == "ec":
            _, _, ecc_min = _resolve_key_length_thresholds(profile)
            if bits < ecc_min:
                boosts.append(
                    (
                        "key_length",
                        V02_BOOST_ECC_LT_MIN,
                        f"EC-{bits} below ecc_minimum ({ecc_min})",
                    )
                )

    # --- cert lifetime boost ---
    if probe.cert_not_after:
        horizon = _resolve_cert_horizon(profile)
        # ISO 8601 YYYY-MM-DD comparisons are lexicographic-safe.
        if probe.cert_not_after > horizon:
            boosts.append(
                (
                    "cert_lifetime",
                    V02_BOOST_CERT_LIFETIME,
                    f"NotAfter={probe.cert_not_after} > "
                    f"horizon={horizon}",
                )
            )

    # --- non-AEAD boost ---
    if probe.aead is False:
        cipher = probe.cipher_suite or "<unknown>"
        boosts.append(
            (
                "non_aead",
                V02_BOOST_NON_AEAD,
                f"non-AEAD cipher: {cipher}",
            )
        )

    # Defensive: enforce per-contribution cap so a future constant
    # change cannot silently break the documented invariant.
    capped: list[tuple[str, float, str]] = []
    for name, delta, why in boosts:
        if delta > V02_MAX_PER_CONTRIBUTION:
            capped.append(
                (
                    name,
                    V02_MAX_PER_CONTRIBUTION,
                    f"{why} [per-contribution cap]",
                )
            )
        else:
            capped.append((name, delta, why))
    return capped


def _clamp_total_boost(
    boosts: list[tuple[str, float, str]],
) -> tuple[float, list[tuple[str, float, str]]]:
    """Clamp the total of ``boosts`` to ``V02_MAX_TOTAL_BOOST``.

    Returns ``(total_after_clamp, scaled_boosts)``. Proportional scaling
    is applied if the raw total exceeds the cap; clamped contributions
    have ``[clamped]`` appended to their rationale.
    """
    if not boosts:
        return 0.0, boosts
    total = sum(d for _, d, _ in boosts)
    if total <= V02_MAX_TOTAL_BOOST:
        return total, boosts
    scale = V02_MAX_TOTAL_BOOST / total
    scaled = [
        (name, delta * scale, f"{why} [clamped]")
        for name, delta, why in boosts
    ]
    return V02_MAX_TOTAL_BOOST, scaled


def score_finding(
    finding: AuditFinding,
    profile: ThreatProfile,
) -> AuditFinding:
    """Return a copy of ``finding`` with score + severity populated.

    Pure function: does not mutate input. The original ``finding.roadmap``
    is preserved (the roadmap layer fills it in *after* scoring).

    When :attr:`ThreatProfile.enable_v02_scoring` is ``True`` (default),
    v0.2 boosts derived from :class:`ProbeResult` extras are added to
    the baseline ``category_weight * archival_likelihood`` and the
    rationale is appended with a ``v0.2 boosts: ...`` segment listing
    each contribution.
    """
    weight = profile.category_weights[finding.category]
    baseline = weight * profile.archival_likelihood

    boosts: list[tuple[str, float, str]] = []
    total_boost = 0.0
    if profile.enable_v02_scoring:
        raw = _compute_v02_boosts(finding.probe, profile)
        total_boost, boosts = _clamp_total_boost(raw)

    score = baseline + total_boost
    # Clamp into [0.0, 1.0] for floating-point safety.
    if score < 0.0:
        score = 0.0
    elif score > 1.0:
        score = 1.0
    severity = severity_for(score, profile)

    rationale = finding.rationale
    if boosts:
        contribs = ", ".join(
            f"{name}+{delta:.3f} ({why})" for name, delta, why in boosts
        )
        rationale = f"{rationale}; v0.2 boosts: {contribs}"

    return finding.model_copy(
        update={
            "score": score,
            "severity": severity,
            "rationale": rationale,
        }
    )


def explain_finding(
    finding: AuditFinding,
    profile: ThreatProfile,
) -> str:
    """Return a multi-line breakdown of how ``finding.score`` was computed.

    Used by ``qwashed audit run --explain`` to surface each contribution
    so a civil-society IT team can see *why* a target landed where it
    did. Pure function: does not consult any state outside its arguments.

    The output format is stable but not part of the signed report (it is
    rendered to stderr / a separate file). Lines:

    * ``target=...`` -- host/port + protocol
    * ``category=... (baseline=W*A=...)`` -- category weight x archival
    * ``boost ...`` -- one line per v0.2 contribution
    * ``total_boost=...`` -- sum after clamp
    * ``score=...`` (final, post-clamp) and ``severity=...``
    """
    target = finding.target
    if target.protocol in {"pgp", "smime"}:
        target_str = f"{target.protocol}:{target.key_path or '<missing>'}"
    else:
        target_str = f"{target.protocol}://{target.host}:{target.port}"
    if target.label:
        target_str = f"{target_str} [{target.label}]"

    weight = profile.category_weights[finding.category]
    baseline = weight * profile.archival_likelihood
    lines = [
        f"target={target_str}",
        f"category={finding.category}",
        f"baseline = category_weight[{finding.category}]={weight:.3f}"
        f" * archival_likelihood={profile.archival_likelihood:.3f}"
        f" = {baseline:.3f}",
    ]

    if profile.enable_v02_scoring:
        raw = _compute_v02_boosts(finding.probe, profile)
        total_boost, boosts = _clamp_total_boost(raw)
        if not boosts:
            lines.append("boosts: (none)")
        else:
            for name, delta, why in boosts:
                lines.append(f"  boost {name}: +{delta:.3f}  ({why})")
            lines.append(f"total_boost={total_boost:.3f}")
    else:
        lines.append("boosts: (disabled by profile.enable_v02_scoring=False)")

    lines.append(f"score={finding.score:.3f}  severity={finding.severity}")
    return "\n".join(lines)


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
