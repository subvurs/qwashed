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
    ("pgp", "classical"): [
        "Generate a hybrid Ed25519+ML-DSA-65 OpenPGP key (algorithm 30 "
        "or the equivalent multi-key bundle) once your OpenPGP "
        "implementation supports RFC 9580 hybrid algorithms.",
        "Until hybrid PQ OpenPGP keys are available in your toolchain, "
        "rotate to a fresh Ed25519 primary key with an X25519 encryption "
        "subkey; this is not PQ-safe but is the strongest classical "
        "OpenPGP posture in 2026.",
        "Republish updated keys to your key directory (WKD, Hagrid, or "
        "internal keyring) and notify correspondents of the fingerprint "
        "change so they can re-verify.",
        "Retain the old classical key only for decrypting historical "
        "ciphertext; do not use it for new encryption or signing.",
    ],
    ("pgp", "hybrid_pq"): [
        "Hybrid PQ OpenPGP key in place. Verify the hybrid pairing "
        "matches the RFC 9580 / draft-ietf-openpgp-pqc choice your "
        "correspondents support.",
        "Continue distributing the public key via your key directory "
        "and update key servers when fingerprints rotate.",
    ],
    ("pgp", "pq_only"): [
        "Pure-PQ OpenPGP keys are uncommon and may not interoperate with "
        "all correspondents. Verify this is intentional; for most users "
        "hybrid PQ is the safer default.",
        "Track NIST and IETF guidance for any PQ primitive deprecation; "
        "pure-PQ keys must rotate quickly if a flaw is announced.",
    ],
    ("pgp", "unknown"): [
        "Probe could not classify the PGP key algorithm. Confirm the "
        "file is a PGP public-key block (not a private key, not a "
        "keyring export) and re-run.",
        "If the algorithm wire-name is genuinely missing from the "
        "Qwashed tables, capture it and submit it via the Qwashed "
        "issue tracker.",
        "Treat the key as classical-equivalent until the algorithm is "
        "recognized.",
    ],
    ("smime", "classical"): [
        "Once your CA supports it, request a hybrid Ed25519+ML-DSA-65 "
        "S/MIME certificate; in the interim, an Ed25519 leaf chained "
        "to an Ed25519 issuer is the strongest classical posture.",
        "Disable RSA-PKCS#1-v1.5 signature algorithms (sha256_with_rsa "
        "etc.) where possible; prefer RSASSA-PSS or EdDSA leaves.",
        "If signing under PKCS#7 / CMS, ensure the digest algorithm is "
        "SHA-256 or stronger; reject SHA-1-signed certificates.",
        "Plan for a chain-wide migration: a hybrid leaf under a "
        "classical issuer is still classical-protected at the trust "
        "anchor.",
    ],
    ("smime", "hybrid_pq"): [
        "Hybrid PQ S/MIME certificate in place. Verify the chain (root + "
        "issuer + leaf) is hybrid-PQ end-to-end; a hybrid leaf under a "
        "classical issuer is still classical-bound at the trust anchor.",
        "Track CA roadmap announcements; some hybrid PQ profiles in "
        "current drafts may be reissued under the final RFC.",
    ],
    ("smime", "pq_only"): [
        "Pure-PQ S/MIME certificates are rare and may break "
        "interoperation with older clients (e.g., legacy email "
        "gateways). Verify this is intentional.",
        "Continue tracking NIST / IETF PQ-cert profile guidance; pure-PQ "
        "certificates must be rotated promptly if a primitive is "
        "deprecated.",
    ],
    ("smime", "unknown"): [
        "Probe could not classify the certificate's algorithms. Confirm "
        "the file is a leaf X.509 certificate (PEM or DER), not a "
        "PKCS#12 bundle or a private key.",
        "If the algorithm OIDs or curve names are genuinely missing "
        "from the Qwashed tables, capture them and submit via the "
        "Qwashed issue tracker.",
        "Treat as classical-equivalent until the algorithm is recognized.",
    ],
}


#: Per-status notes for non-OK probes.
_ROADMAP_NON_OK: Final[dict[str, list[str]]] = {
    "unreachable": [
        "Probe could not reach the target. For network targets check "
        "DNS, firewall rules, and that the service is listening on the "
        "expected port. For file targets (PGP / S/MIME) check that "
        "key_path exists and is readable by the audit process.",
        "If the target is intentionally not exposed to the audit host, "
        "remove it from the audit list.",
    ],
    "malformed": [
        "Target responded but the data was not a valid TLS / SSH "
        "handshake or PGP / S/MIME key file. Possible causes: wrong "
        "port, plaintext service behind a TLS terminator, captive-"
        "portal interference, truncated or non-key file at key_path, "
        "or ASCII-armored data with corrupted base64 body.",
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
