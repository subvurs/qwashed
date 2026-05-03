# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Pydantic schemas for the Qwashed HNDL auditor.

Data flow
---------
::

    AuditTarget ----probe.py----> ProbeResult
                                        |
                                  classifier.py
                                        v
                                  AuditFinding
                                        |
                                   scoring.py
                                        v
                              AuditFinding (+score)
                                        |
                                  roadmap.py
                                        v
                          AuditFinding (+roadmap)
                                        |
                              (collect across targets)
                                        v
                                  AuditReport ---signing/canonical---> signed JSON

Every model inherits :class:`StrictBaseModel` (frozen, ``extra="forbid"``).
Strings are stripped of leading/trailing whitespace at validation time so the
classic ``" RSA"`` vs ``"RSA"`` mismatch cannot bite the classifier.

The :class:`ThreatProfile` schema is the YAML-loaded scoring profile shipped
in ``qwashed/audit/profiles/`` and selected by ``--profile`` on the command
line. Its weights MUST sum to 1.0 within ``WEIGHT_SUM_TOLERANCE``; otherwise
:class:`SchemaValidationError` is raised at load time.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, Field, field_validator, model_validator

from qwashed.core.schemas import StrictBaseModel, nonempty_str

__all__ = [
    "WEIGHT_SUM_TOLERANCE",
    "AuditFinding",
    "AuditReport",
    "AuditTarget",
    "Category",
    "ProbeResult",
    "ProbeStatus",
    "ProtocolKind",
    "Severity",
    "ThreatProfile",
]

#: Allowed floating-point error in :attr:`ThreatProfile.weights` summing to 1.0.
WEIGHT_SUM_TOLERANCE: float = 1e-6

#: Category labels emitted by :mod:`qwashed.audit.classifier`.
#:
#: * ``classical`` -- only RSA / ECDSA / classical DH; HNDL-vulnerable.
#: * ``hybrid_pq`` -- classical || PQ co-installed (e.g. X25519MLKEM768).
#: * ``pq_only``   -- pure PQ; theoretically future-proof but rare in 2026.
#: * ``unknown``   -- probe completed but algorithm not in our table; treated
#:   as worst-case for fail-closed scoring.
Category = Literal["classical", "hybrid_pq", "pq_only", "unknown"]

#: Whether the probe even reached the target.
#:
#: * ``ok``         -- handshake completed, algorithms recovered.
#: * ``unreachable``-- network error, DNS failure, timeout (no handshake).
#: * ``malformed``  -- target answered but TLS / SSH framing was invalid.
#: * ``refused``    -- target actively refused (e.g. TLS alert, RST).
ProbeStatus = Literal["ok", "unreachable", "malformed", "refused"]

#: Protocols supported in v0.1; SSH is feature-flagged in :mod:`probe` but
#: defined here so the schema is stable across the v0.1 minor series.
ProtocolKind = Literal["tls", "ssh"]

#: Severity bucket for a single finding. Maps onto the score tiers in
#: :mod:`qwashed.audit.scoring`.
Severity = Literal["info", "low", "moderate", "high", "critical"]


class AuditTarget(StrictBaseModel):
    """A single host:port to audit.

    Parameters
    ----------
    host:
        Hostname or IPv4/IPv6 literal. Whitespace stripped; validated
        non-empty. We do not resolve here; the probe layer handles
        resolution and reports DNS failure as ``ProbeStatus.unreachable``.
    port:
        TCP port (1-65535).
    protocol:
        ``"tls"`` or ``"ssh"``. SSH probing is gated behind the ``[audit-ssh]``
        extra; CLI rejects ``"ssh"`` targets unless the extra is installed.
    label:
        Optional human-readable identifier carried through to the report
        (e.g. ``"intake-mailserver-prod"``). Useful when many hosts share
        a name template.
    """

    host: Annotated[str, AfterValidator(nonempty_str)]
    port: int = Field(ge=1, le=65535)
    protocol: ProtocolKind = "tls"
    label: str | None = None


class ProbeResult(StrictBaseModel):
    """Raw output of a probe attempt against one target.

    Carries enough information for the classifier to make a deterministic
    decision and for the report to show *why* a target was scored where it
    was. Algorithm names are kept as the protocol's wire identifiers
    (e.g. ``"TLS_AES_128_GCM_SHA256"``, ``"X25519MLKEM768"``); the classifier
    does the lookup.
    """

    target: AuditTarget
    status: ProbeStatus
    #: Protocol-version string the server negotiated, e.g. ``"TLSv1.3"``.
    #: Empty string when ``status != "ok"``.
    negotiated_protocol_version: str = ""
    #: Cipher suite identifier, e.g. ``"TLS_AES_128_GCM_SHA256"``. Empty
    #: when ``status != "ok"``.
    cipher_suite: str = ""
    #: Key-exchange group / named curve, e.g. ``"X25519"``,
    #: ``"X25519MLKEM768"``, ``"secp256r1"``. Empty if not negotiated.
    key_exchange_group: str = ""
    #: Signature algorithm used for server certificate / handshake,
    #: e.g. ``"rsa_pss_rsae_sha256"``, ``"ed25519"``,
    #: ``"mldsa65_with_ed25519"``. Empty if unknown.
    signature_algorithm: str = ""
    #: Free-form additional protocol details (e.g. SSH KEX list, TLS
    #: groups offered). Bounded to small strings; pydantic enforces no
    #: nested objects via ``StrictBaseModel.extra="forbid"``.
    extras: dict[str, str] = Field(default_factory=dict)
    #: Wall-clock elapsed seconds the probe took. Useful for the report;
    #: never used for security decisions.
    elapsed_seconds: float = Field(ge=0.0, default=0.0)
    #: Diagnostic detail when ``status != "ok"``. Should be safe to log;
    #: never includes raw bytes from the wire.
    error_detail: str = ""


class AuditFinding(StrictBaseModel):
    """Per-target classification + score + roadmap."""

    target: AuditTarget
    probe: ProbeResult
    category: Category
    severity: Severity
    #: HNDL exposure score in [0.0, 1.0]; 1.0 = maximum exposure.
    #: Computed by :mod:`qwashed.audit.scoring`; the formula is
    #: deterministic in (category, profile, archival_likelihood).
    score: float = Field(ge=0.0, le=1.0)
    #: Stable rationale string (algorithm name + classification reason).
    rationale: str
    #: Ordered list of remediation steps from :mod:`qwashed.audit.roadmap`.
    roadmap: list[str] = Field(default_factory=list)


class AuditReport(StrictBaseModel):
    """Full output of one ``qwashed audit`` run.

    Designed to be canonicalized via :func:`qwashed.core.canonical.canonicalize`
    and signed via :func:`qwashed.core.signing.SigningKey.sign`. Round-tripping
    through JSON must be lossless: every field is a primitive or a list of
    submodels, no datetimes (we use string ISO 8601 explicitly), no Decimal.
    """

    #: ISO 8601 UTC timestamp ("2026-04-30T17:23:11Z"). Frozen by
    #: ``--deterministic`` so signed artifacts can be reproduced.
    generated_at: str
    #: Profile that drove the scoring (e.g. ``"default"``, ``"journalism"``).
    profile_name: str
    #: Findings, one per target. Ordered as supplied to the auditor.
    findings: list[AuditFinding]
    #: Aggregate score: weighted mean of finding scores. In [0.0, 1.0].
    aggregate_score: float = Field(ge=0.0, le=1.0)
    #: Aggregate severity bucket derived from :attr:`aggregate_score`.
    aggregate_severity: Severity
    #: Qwashed version that produced this report (e.g. ``"0.1.0"``).
    qwashed_version: str

    @field_validator("generated_at")
    @classmethod
    def _generated_at_nonempty(cls, value: str) -> str:
        if not value:
            raise ValueError("generated_at must not be empty")
        return value


class ThreatProfile(StrictBaseModel):
    """YAML-loaded scoring profile.

    The profile defines:

    1. Per-category baseline exposure (``category_weights``). For example,
       a journalism profile sets ``classical=1.0`` because *any* RSA exposure
       on a source-protection mail server is critical.
    2. ``archival_likelihood`` -- prior probability the adversary archives
       this traffic for later decryption. Higher -> higher score.
    3. ``severity_thresholds`` -- where to cut between info/low/moderate/
       high/critical. Different profiles can be tuned to different
       organizational risk tolerances.
    4. ``aggregation`` -- how to combine per-target findings into the
       organizational rollup. ``"max"`` picks the worst target; ``"mean"``
       averages.
    """

    name: Annotated[str, AfterValidator(nonempty_str)]
    description: Annotated[str, AfterValidator(nonempty_str)]
    #: Per-category exposure weights in [0.0, 1.0]. The four keys are
    #: ``classical``, ``hybrid_pq``, ``pq_only``, ``unknown`` and MUST all
    #: be present.
    category_weights: dict[str, float]
    #: Prior on whether this organization's traffic is being archived.
    #: ``[0.0, 1.0]``. Civil-society defaults are typically 0.7+ given
    #: visibility of the threat actor in 2026.
    archival_likelihood: float = Field(ge=0.0, le=1.0)
    #: Cutoffs from score in [0.0, 1.0] to severity bucket. Must be in
    #: monotonic non-decreasing order: info < low < moderate < high < critical.
    severity_thresholds: dict[str, float]
    #: ``"max"`` (worst target dominates) or ``"mean"`` (average).
    aggregation: Literal["max", "mean"] = "max"

    @model_validator(mode="after")
    def _check_weights(self) -> ThreatProfile:
        required = {"classical", "hybrid_pq", "pq_only", "unknown"}
        missing = required - self.category_weights.keys()
        if missing:
            raise ValueError(
                f"category_weights missing keys: {sorted(missing)}",
            )
        extra = self.category_weights.keys() - required
        if extra:
            raise ValueError(
                f"category_weights has unknown keys: {sorted(extra)}",
            )
        for cat, w in self.category_weights.items():
            if not (0.0 <= w <= 1.0):
                raise ValueError(
                    f"category_weights[{cat!r}] must be in [0.0, 1.0], got {w}",
                )
        # Domain-monotonic check: classical >= hybrid_pq >= pq_only and
        # unknown >= hybrid_pq (we treat unknown as worst-case-classical
        # for fail-closed scoring).
        cw = self.category_weights
        if cw["classical"] < cw["hybrid_pq"]:
            raise ValueError(
                "weights[classical] must be >= weights[hybrid_pq]",
            )
        if cw["hybrid_pq"] < cw["pq_only"]:
            raise ValueError(
                "weights[hybrid_pq] must be >= weights[pq_only]",
            )
        if cw["unknown"] < cw["hybrid_pq"]:
            raise ValueError(
                "weights[unknown] must be >= weights[hybrid_pq] (fail-closed)",
            )
        return self

    @model_validator(mode="after")
    def _check_severity_thresholds(self) -> ThreatProfile:
        required = {"info", "low", "moderate", "high", "critical"}
        missing = required - self.severity_thresholds.keys()
        if missing:
            raise ValueError(
                f"severity_thresholds missing keys: {sorted(missing)}",
            )
        extra = self.severity_thresholds.keys() - required
        if extra:
            raise ValueError(
                f"severity_thresholds has unknown keys: {sorted(extra)}",
            )
        order = ["info", "low", "moderate", "high", "critical"]
        last = -1.0
        for key in order:
            v = self.severity_thresholds[key]
            if not (0.0 <= v <= 1.0):
                raise ValueError(
                    f"severity_thresholds[{key!r}] must be in [0.0, 1.0], got {v}",
                )
            if v < last:
                raise ValueError(
                    "severity_thresholds must be monotonic non-decreasing "
                    f"(info <= low <= moderate <= high <= critical); {key}={v}"
                    f" came after {last}",
                )
            last = v
        return self
