# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Classify a :class:`ProbeResult` into a HNDL exposure category.

The classifier is a pure function over the probe output. It does no I/O,
no network access, and never raises on unrecognized input -- unrecognized
algorithms are mapped to ``"unknown"`` (which the scoring layer treats as
worst-case-classical). This is the fail-closed posture: an unknown
algorithm cannot accidentally be treated as PQ-protected.

Decision rule (highest priority wins):

1. If status != "ok": category = "unknown" (probe couldn't observe anything).
2. If KEX group is hybrid_pq OR signature is hybrid_pq: category = "hybrid_pq".
3. If KEX group is pq_only AND signature is pq_only: category = "pq_only".
4. If KEX group is pq_only XOR signature is pq_only: category = "hybrid_pq"
   (one PQ + one classical = hybrid in spirit).
5. If KEX group is classical AND signature is classical: category = "classical".
6. Otherwise (anything unrecognized): category = "unknown".

For PGP targets, the only field that matters is the primary public-key
algorithm; the classifier looks it up in ``pgp_public_key_algorithms``
and returns that category directly. For S/MIME targets, the cert's
SubjectPublicKeyInfo algorithm and signature algorithm are combined via
the same _combine() decision table as TLS / SSH KEX vs signature.

The rationale string captured on the resulting :class:`AuditFinding` records
*which* algorithm drove the decision, so a human reviewer can audit it.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Final

from qwashed.audit.schemas import AuditFinding, Category, ProbeResult, Severity
from qwashed.core.errors import ConfigurationError

__all__ = [
    "AlgorithmTables",
    "classify",
    "classify_algorithm",
    "load_algorithm_tables",
]

#: Severity placeholder; scoring.py replaces this on every finding.
#: The classifier sets it to "info" so the schema is satisfied; the real
#: severity is computed downstream from the score.
_SEVERITY_PLACEHOLDER: Final[Severity] = "info"


class AlgorithmTables:
    """Loaded view over ``algorithm_tables.json``.

    Each ``classify_*`` method takes a single algorithm wire-name and
    returns one of ``"classical"``, ``"hybrid_pq"``, ``"pq_only"``, or
    ``"unknown"``. The lookup is case-insensitive for SSH names (which
    are lowercase by convention) and case-sensitive for TLS cipher
    suite identifiers (which are upper-snake-case by IANA).
    """

    __slots__ = (
        "_pgp_public_key",
        "_smime_public_key",
        "_smime_signature",
        "_ssh_hostkey",
        "_ssh_kex",
        "_tls_cipher",
        "_tls_kex",
        "_tls_sig",
    )

    def __init__(self, raw: dict) -> None:  # type: ignore[type-arg]
        self._tls_kex = self._index(raw.get("tls_key_exchange_groups", {}), lower=True)
        self._tls_sig = self._index(raw.get("tls_signature_algorithms", {}), lower=True)
        self._tls_cipher = self._index(raw.get("tls_cipher_suites", {}), lower=False)
        self._ssh_kex = self._index(raw.get("ssh_key_exchange", {}), lower=True)
        self._ssh_hostkey = self._index(raw.get("ssh_host_key_algorithms", {}), lower=True)
        self._pgp_public_key = self._index(
            raw.get("pgp_public_key_algorithms", {}), lower=True,
        )
        self._smime_public_key = self._index(
            raw.get("smime_public_key_algorithms", {}), lower=True,
        )
        self._smime_signature = self._index(
            raw.get("smime_signature_algorithms", {}), lower=True,
        )

    @staticmethod
    def _index(
        section: dict,  # type: ignore[type-arg]
        *,
        lower: bool,
    ) -> dict[str, Category]:
        out: dict[str, Category] = {}
        for cat, names in section.items():
            if cat not in {"classical", "hybrid_pq", "pq_only"}:
                continue
            if not isinstance(names, list):
                continue
            for n in names:
                if not isinstance(n, str):
                    continue
                key = n.lower() if lower else n
                out[key] = cat
        return out

    def classify_tls_kex(self, name: str) -> Category:
        return self._tls_kex.get(name.strip().lower(), "unknown")

    def classify_tls_signature(self, name: str) -> Category:
        return self._tls_sig.get(name.strip().lower(), "unknown")

    def classify_tls_cipher(self, name: str) -> Category:
        return self._tls_cipher.get(name.strip(), "unknown")

    def classify_ssh_kex(self, name: str) -> Category:
        return self._ssh_kex.get(name.strip().lower(), "unknown")

    def classify_ssh_hostkey(self, name: str) -> Category:
        return self._ssh_hostkey.get(name.strip().lower(), "unknown")

    def classify_pgp_public_key(self, name: str) -> Category:
        return self._pgp_public_key.get(name.strip().lower(), "unknown")

    def classify_smime_public_key(self, name: str) -> Category:
        return self._smime_public_key.get(name.strip().lower(), "unknown")

    def classify_smime_signature(self, name: str) -> Category:
        return self._smime_signature.get(name.strip().lower(), "unknown")


@lru_cache(maxsize=1)
def load_algorithm_tables() -> AlgorithmTables:
    """Load and cache the bundled algorithm tables.

    Cached for the process lifetime; the JSON file is package data and
    does not change at runtime.
    """
    try:
        traversable = resources.files("qwashed.audit") / "algorithm_tables.json"
    except ModuleNotFoundError as exc:  # pragma: no cover - defensive
        raise ConfigurationError(
            f"audit package missing: {exc}",
            error_code="audit.classifier.missing_package",
        ) from exc
    if not traversable.is_file():
        raise ConfigurationError(
            "algorithm_tables.json missing from package",
            error_code="audit.classifier.missing_table",
        )
    try:
        raw = json.loads(traversable.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigurationError(
            f"algorithm_tables.json is not valid JSON: {exc}",
            error_code="audit.classifier.bad_json",
        ) from exc
    if not isinstance(raw, dict):
        raise ConfigurationError(
            "algorithm_tables.json must be a JSON object at the top level",
            error_code="audit.classifier.not_object",
        )
    return AlgorithmTables(raw)


def classify_algorithm(
    *,
    protocol: str,
    field: str,
    name: str,
    tables: AlgorithmTables | None = None,
) -> Category:
    """Classify a single algorithm name.

    Parameters
    ----------
    protocol:
        ``"tls"``, ``"ssh"``, ``"pgp"``, or ``"smime"``.
    field:
        For TLS: ``"kex"``, ``"signature"``, or ``"cipher"``.
        For SSH: ``"kex"`` or ``"hostkey"``.
        For PGP: ``"public_key"``.
        For S/MIME: ``"public_key"`` or ``"signature"``.
    name:
        The wire-name of the algorithm.
    tables:
        Optional :class:`AlgorithmTables`; if omitted, the bundled tables
        are loaded.

    Returns
    -------
    Category
        ``"classical"``, ``"hybrid_pq"``, ``"pq_only"``, or ``"unknown"``.
        Empty input ``name`` -> ``"unknown"``.
    """
    if not name:
        return "unknown"
    t = tables or load_algorithm_tables()
    if protocol == "tls":
        if field == "kex":
            return t.classify_tls_kex(name)
        if field == "signature":
            return t.classify_tls_signature(name)
        if field == "cipher":
            return t.classify_tls_cipher(name)
    elif protocol == "ssh":
        if field == "kex":
            return t.classify_ssh_kex(name)
        if field == "hostkey":
            return t.classify_ssh_hostkey(name)
    elif protocol == "pgp":
        if field == "public_key":
            return t.classify_pgp_public_key(name)
    elif protocol == "smime":
        if field == "public_key":
            return t.classify_smime_public_key(name)
        if field == "signature":
            return t.classify_smime_signature(name)
    raise ConfigurationError(
        f"unknown protocol/field combination: {protocol!r}/{field!r}",
        error_code="audit.classifier.bad_field",
    )


def classify(
    probe: ProbeResult,
    tables: AlgorithmTables | None = None,
) -> AuditFinding:
    """Classify a probe result into an :class:`AuditFinding`.

    The returned finding has placeholder severity and score; the scoring
    layer fills those in. The :attr:`AuditFinding.rationale` records the
    KEX and signature names + their per-algorithm classifications so a
    human can audit *why* the decision was made.
    """
    if probe.status != "ok":
        rationale = (
            f"probe status={probe.status!r}: "
            f"{probe.error_detail or 'no detail'}; "
            "treated as unknown for fail-closed scoring"
        )
        return AuditFinding(
            target=probe.target,
            probe=probe,
            category="unknown",
            severity=_SEVERITY_PLACEHOLDER,
            score=0.0,
            rationale=rationale,
        )

    t = tables or load_algorithm_tables()
    proto = probe.target.protocol

    if proto == "tls":
        kex_cat = t.classify_tls_kex(probe.key_exchange_group)
        sig_cat = t.classify_tls_signature(probe.signature_algorithm)
        cipher_cat = t.classify_tls_cipher(probe.cipher_suite)
        # TLS 1.3 ciphers are symmetric only; treat unknown cipher as
        # informational unless KEX/sig also unknown.
        category = _combine(kex_cat, sig_cat)
        rationale = (
            f"TLS kex={probe.key_exchange_group!r} ({kex_cat}); "
            f"signature={probe.signature_algorithm!r} ({sig_cat}); "
            f"cipher={probe.cipher_suite!r} ({cipher_cat}) -> {category}"
        )
    elif proto == "ssh":
        kex_cat = t.classify_ssh_kex(probe.key_exchange_group)
        sig_cat = t.classify_ssh_hostkey(probe.signature_algorithm)
        category = _combine(kex_cat, sig_cat)
        rationale = (
            f"SSH kex={probe.key_exchange_group!r} ({kex_cat}); "
            f"hostkey={probe.signature_algorithm!r} ({sig_cat}) -> {category}"
        )
    elif proto == "pgp":
        # PgpProbe stashes the primary public-key algorithm wire-name in
        # ProbeResult.signature_algorithm (the field is repurposed for
        # the algorithm being classified across protocols).
        pk_cat = t.classify_pgp_public_key(probe.signature_algorithm)
        category = pk_cat
        rationale = (
            f"PGP primary public-key algorithm="
            f"{probe.signature_algorithm!r} ({pk_cat}) -> {category}"
        )
    elif proto == "smime":
        # SmimeProbe stashes the SubjectPublicKeyInfo algorithm in
        # ProbeResult.key_exchange_group and the cert's signatureAlgorithm
        # in ProbeResult.signature_algorithm.
        pk_cat = t.classify_smime_public_key(probe.key_exchange_group)
        sig_cat = t.classify_smime_signature(probe.signature_algorithm)
        category = _combine(pk_cat, sig_cat)
        rationale = (
            f"S/MIME public_key={probe.key_exchange_group!r} ({pk_cat}); "
            f"signature={probe.signature_algorithm!r} ({sig_cat}) -> "
            f"{category}"
        )
    else:  # pragma: no cover - schema rejects this earlier
        raise ConfigurationError(
            f"unsupported protocol in probe: {proto!r}",
            error_code="audit.classifier.bad_protocol",
        )

    return AuditFinding(
        target=probe.target,
        probe=probe,
        category=category,
        severity=_SEVERITY_PLACEHOLDER,
        score=0.0,
        rationale=rationale,
    )


def _combine(kex: Category, sig: Category) -> Category:
    """Combine KEX and signature classifications into an overall category.

    Decision table (rows = KEX, cols = signature)::

                        | classical | hybrid_pq | pq_only | unknown
        ----------------+-----------+-----------+---------+--------
        classical       | classical | hybrid_pq | hybrid* | unknown
        hybrid_pq       | hybrid_pq | hybrid_pq | hybrid_pq | unknown
        pq_only         | hybrid*   | hybrid_pq | pq_only | unknown
        unknown         | unknown   | unknown   | unknown | unknown

    ``hybrid*``: one PQ component + one classical component. Treated as
    ``hybrid_pq`` because the deployment has at least one PQ leg, even if
    the asymmetry means the reduction is not formally a hybrid construction.
    Any ``unknown`` propagates to the result -- fail-closed.
    """
    if kex == "unknown" or sig == "unknown":
        return "unknown"
    if kex == "hybrid_pq" or sig == "hybrid_pq":
        return "hybrid_pq"
    if kex == "pq_only" and sig == "pq_only":
        return "pq_only"
    if kex == "pq_only" or sig == "pq_only":
        return "hybrid_pq"
    return "classical"
