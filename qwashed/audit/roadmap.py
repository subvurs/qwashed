# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Migration-roadmap recommendations for Qwashed audit findings.

The roadmap layer translates a classified, scored :class:`AuditFinding`
into a list of concrete remediation steps that a non-cryptographer
sysadmin can act on. Recommendations are *advisory*: they are deliberately
broad ("enable hybrid X25519MLKEM768 on your TLS terminator") rather than
vendor-specific ("on nginx 1.27, set ssl_ecdh_curve = ...") -- the
v0.1 product avoids vendor lock-in by leaving the implementation
specifics to the human.

The recommendation table is data, not code: any reviewer who disagrees
with the wording can edit it without touching control flow.

Each output step is a self-contained sentence, English, no markdown,
suitable for both the JSON artifact and the HTML report.
"""

from __future__ import annotations

from typing import Final

from qwashed.audit.schemas import AuditFinding, Category, Severity

__all__ = [
    "ROADMAP_TABLE",
    "attach_roadmap",
    "build_roadmap",
]


#: Per-(protocol, category) baseline recommendations.
#:
#: These are the steps that always apply for the (protocol, category)
#: combination. The :func:`build_roadmap` function then layers
#: severity-specific urgency notes on top.
_ROADMAP_BASELINE: Final[dict[tuple[str, Category], list[str]]] = {
    ("tls", "classical"): [
        "Enable hybrid post-quantum TLS key exchange on the server "
        "(X25519MLKEM768 is the IETF-standardized choice as of 2026).",
        "Pair hybrid KEX with a hybrid Ed25519+ML-DSA-65 certificate "
        "chain when the upstream CA supports it; until then the existing "
        "classical certificate is acceptable as long as KEX is hybrid.",
        "Disable TLS 1.0/1.1 if still enabled; the hybrid groups require TLS 1.3.",
        "Audit cipher-suite policy: keep AES-GCM and ChaCha20-Poly1305 "
        "AEAD; remove RSA key-exchange suites entirely.",
    ],
    ("tls", "hybrid_pq"): [
        "Hybrid PQ key exchange is in place. Verify the deployed group "
        "matches the IETF-standardized X25519MLKEM768 (RFC 9794) rather "
        "than an early experimental hybrid that may be deprecated.",
        "Track the IETF roadmap for migration to hybrid certificate "
        "chains (Ed25519+ML-DSA-65) once your CA offers them.",
        "Continue monitoring for downgrade attempts: hybrid-only policy "
        "is preferable to hybrid-preferred-but-classical-fallback.",
    ],
    ("tls", "pq_only"): [
        "Pure-PQ TLS is rare in 2026 and reduces interoperability with "
        "older clients. Verify this is intentional; for most civil-society "
        "deployments hybrid PQ is the safer choice.",
        "Continue monitoring NIST and IETF guidance for potential PQ "
        "primitive deprecation; pure-PQ deployments must migrate quickly "
        "if a flaw is announced.",
    ],
    ("tls", "unknown"): [
        "Probe could not classify the negotiated TLS algorithms. Re-run "
        "the audit with --verbose to capture the wire identifiers, then "
        "report them via the Qwashed issue tracker so the algorithm "
        "tables can be updated.",
        "Until classification is resolved, treat this endpoint as "
        "classical-equivalent and apply the classical-TLS roadmap.",
    ],
    ("ssh", "classical"): [
        "Enable a hybrid post-quantum SSH KEX algorithm such as "
        "sntrup761x25519-sha512@openssh.com or mlkem768x25519-sha256.",
        "Update OpenSSH to 9.6+ on both server and client to gain post-quantum hybrid support.",
        "Continue using ssh-ed25519 host keys; PQ host-key migration is "
        "not yet standardized but hybrid KEX already protects session "
        "establishment.",
        "Disable diffie-hellman-group14-sha1 and other SHA-1 KEX variants.",
    ],
    ("ssh", "hybrid_pq"): [
        "Hybrid PQ SSH key exchange is in place. Verify both sides "
        "agree on the same algorithm and that the algorithm has not "
        "been deprecated (sntrup761x25519 is being superseded by ML-KEM-"
        "based variants).",
        "Audit fallback policy: prefer hybrid-only rather than allowing "
        "fallback to classical curve25519-sha256.",
    ],
    ("ssh", "pq_only"): [
        "Pure-PQ SSH KEX is uncommon. Verify it was set deliberately; "
        "interop with older clients will fail.",
    ],
    ("ssh", "unknown"): [
        "Probe could not classify the SSH algorithms. Re-run with "
        "--verbose, capture the KEX and host-key names, and submit them "
        "to the Qwashed issue tracker for inclusion in the algorithm "
        "tables.",
        "Treat as classical-equivalent until the algorithm is recognized.",
    ],
}


#: Per-status notes for non-OK probes.
_ROADMAP_NON_OK: Final[dict[str, list[str]]] = {
    "unreachable": [
        "Probe could not reach the target. Check DNS, firewall rules, "
        "and that the service is listening on the expected port.",
        "If the target is intentionally not exposed to the audit host, "
        "remove it from the audit list.",
    ],
    "malformed": [
        "Target responded but the response was not a valid TLS or SSH "
        "handshake. Possible causes: wrong port, plaintext service "
        "behind a TLS terminator, captive-portal interference.",
    ],
    "refused": [
        "Target actively refused the connection. Verify the service is "
        "running and that the audit host is not on a deny-list.",
    ],
}


#: Severity-specific urgency notes prepended to the roadmap.
_URGENCY_NOTES: Final[dict[Severity, str]] = {
    "critical": (
        "URGENT: this finding scores in the critical tier under the "
        "selected threat profile. Treat as a top-priority migration."
    ),
    "high": ("HIGH PRIORITY: schedule remediation within the current operational quarter."),
    "moderate": ("MODERATE: include in the next planned configuration review."),
    "low": (
        "LOW: acceptable in the short term; track for the next long-cycle infrastructure update."
    ),
    "info": ("INFORMATIONAL: no immediate action required."),
}


#: Public, frozen view of the recommendation table for documentation /
#: external review. Tuple of (key, recommendations) entries.
ROADMAP_TABLE: tuple[tuple[tuple[str, Category], tuple[str, ...]], ...] = tuple(
    (key, tuple(recs)) for key, recs in _ROADMAP_BASELINE.items()
)


def build_roadmap(finding: AuditFinding) -> list[str]:
    """Return an ordered list of remediation steps for ``finding``.

    The first item is the urgency note (severity-keyed). The remaining
    items are the (protocol, category)-keyed baseline plus, when the
    probe failed, a status-specific operational note.

    Pure function: identical input always produces identical output.
    """
    steps: list[str] = []
    steps.append(_URGENCY_NOTES[finding.severity])

    if finding.probe.status != "ok":
        steps.extend(_ROADMAP_NON_OK.get(finding.probe.status, []))

    proto = finding.target.protocol
    key = (proto, finding.category)
    baseline = _ROADMAP_BASELINE.get(key, [])
    steps.extend(baseline)
    return steps


def attach_roadmap(finding: AuditFinding) -> AuditFinding:
    """Return a copy of ``finding`` with :attr:`roadmap` populated.

    Convenience for the audit pipeline: classifier -> scoring -> this
    function -> finished finding.
    """
    return finding.model_copy(update={"roadmap": build_roadmap(finding)})
