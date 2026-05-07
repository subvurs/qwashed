# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Golden-file tests for the audit pipeline.

These tests run the full ``qwashed audit run --deterministic`` pipeline
against canned probe responses for each bundled threat profile, and
compare the resulting signed JSON byte-for-byte against a locked
baseline file under ``tests/golden/``.

If you change anything that affects the wire format (schemas, scoring
weights, rationales, signing envelope), regenerate the golden files:

    python -m tests.audit.test_golden --regenerate

Then commit the updated baselines alongside the code change. This keeps
"deterministic by design" as an enforced property rather than a hope.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from qwashed.audit import cli as audit_cli
from qwashed.audit.probe import StaticProbe
from qwashed.audit.schemas import AuditTarget, ProbeResult
from qwashed.cli import main as qwashed_main

GOLDEN_DIR = Path(__file__).resolve().parents[1] / "golden"
EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "examples" / "audit"


# ---------------------------------------------------------------------------
# Canned probe responses keyed off (host, port).
# ---------------------------------------------------------------------------


def _ok(host: str, port: int, **fields: Any) -> ProbeResult:
    return ProbeResult(
        target=AuditTarget(host=host, port=port),
        status="ok",
        **fields,
    )


# v0.2 (§3.5) probe metadata: a 2048-bit RSA leaf cert with NotAfter
# inside the horizon and an AEAD cipher. This represents a typical
# "well-configured but classical" deployment — the v0.2 boosts should
# all stay zero so the v0.1-vs-v0.2 wire diff for these targets only
# adds the new fields with their default values.
_DEFAULT_TLS_FIELDS: dict[str, Any] = {
    "negotiated_protocol_version": "TLSv1.3",
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "key_exchange_group": "X25519",
    "signature_algorithm": "rsa_pss_rsae_sha256",
    "public_key_bits": 2048,
    "public_key_algorithm_family": "rsa",
    "cert_not_after": "2027-03-15",
    "aead": True,
}


_HYBRID_TLS_FIELDS: dict[str, Any] = {
    "negotiated_protocol_version": "TLSv1.3",
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "key_exchange_group": "X25519MLKEM768",
    "signature_algorithm": "ed25519",
    "public_key_bits": 256,
    "public_key_algorithm_family": "ec",
    "cert_not_after": "2027-09-01",
    "aead": True,
}


_CANNED: dict[tuple[str, int], ProbeResult] = {
    # civic_websites.yaml -> classical (X25519 + RSA-PSS)
    ("civic.example.org", 443): _ok("civic.example.org", 443, **_DEFAULT_TLS_FIELDS),
    ("members.example.org", 443): _ok("members.example.org", 443, **_DEFAULT_TLS_FIELDS),
    # healthcare -> hybrid_pq on both
    ("ehr.example-clinic.org", 443): _ok("ehr.example-clinic.org", 443, **_HYBRID_TLS_FIELDS),
    ("portal.example-clinic.org", 443): _ok("portal.example-clinic.org", 443, **_HYBRID_TLS_FIELDS),
    # journalism -> mixed: classical CMS, hybrid securedrop
    ("cms.example-newsroom.org", 443): _ok("cms.example-newsroom.org", 443, **_DEFAULT_TLS_FIELDS),
    ("securedrop.example-newsroom.org", 443): _ok(
        "securedrop.example-newsroom.org", 443, **_HYBRID_TLS_FIELDS
    ),
    # legal -> mixed: classical mail, hybrid case portal
    ("mail.example-lawfirm.org", 443): _ok("mail.example-lawfirm.org", 443, **_DEFAULT_TLS_FIELDS),
    ("cases.example-lawfirm.org", 443): _ok("cases.example-lawfirm.org", 443, **_HYBRID_TLS_FIELDS),
}


@pytest.fixture(autouse=False)
def stub_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the CLI's run_audit with one that injects a StaticProbe."""
    real_run_audit = getattr(audit_cli, "run_audit")  # noqa: B009 - bypass __all__ export check

    def _patched(targets: Any, **kwargs: Any) -> Any:
        kwargs["probe_impl"] = StaticProbe(_CANNED)
        return real_run_audit(targets, **kwargs)

    monkeypatch.setattr(audit_cli, "run_audit", _patched)


# ---------------------------------------------------------------------------
# Golden cases
# ---------------------------------------------------------------------------

GOLDEN_CASES: list[tuple[str, str, str]] = [
    # (config filename, profile name, golden filename)
    ("civic_websites.yaml", "default", "civic_default.json"),
    ("healthcare_endpoints.yaml", "healthcare", "healthcare_healthcare.json"),
    ("journalism_endpoints.yaml", "journalism", "journalism_journalism.json"),
    ("legal_endpoints.yaml", "legal", "legal_legal.json"),
]


def _run_audit_to_bytes(*, config: Path, profile: str, output: Path) -> bytes:
    qwashed_main(
        [
            "audit",
            "run",
            str(config),
            "--profile",
            profile,
            "--output",
            str(output),
            "--deterministic",
        ]
    )
    return output.read_bytes()


@pytest.mark.parametrize("config_name, profile, golden_name", GOLDEN_CASES)
def test_golden_matches(
    tmp_path: Path,
    stub_probe: None,
    config_name: str,
    profile: str,
    golden_name: str,
) -> None:
    config = EXAMPLES_DIR / config_name
    out = tmp_path / "out.json"
    actual = _run_audit_to_bytes(config=config, profile=profile, output=out)

    golden = GOLDEN_DIR / golden_name
    if not golden.is_file():  # pragma: no cover - regeneration path
        pytest.fail(
            f"missing golden file: {golden}. Regenerate with "
            f"`python -m tests.audit.test_golden --regenerate`."
        )
    expected = golden.read_bytes()
    if actual != expected:  # pragma: no cover - golden mismatch surface
        # Surface a readable JSON diff hint, but assert on bytes.
        actual_doc = json.loads(actual)
        expected_doc = json.loads(expected)
        diff_keys = sorted(set(actual_doc) ^ set(expected_doc))
        pytest.fail(
            "golden mismatch for "
            f"{golden_name}: differing keys={diff_keys}. Regenerate with "
            f"`python -m tests.audit.test_golden --regenerate`."
        )


@pytest.mark.parametrize("config_name, profile, _golden_name", GOLDEN_CASES)
def test_golden_is_byte_stable_across_runs(
    tmp_path: Path,
    stub_probe: None,
    config_name: str,
    profile: str,
    _golden_name: str,
) -> None:
    """Two consecutive --deterministic runs produce identical bytes."""
    config = EXAMPLES_DIR / config_name
    out1 = tmp_path / "r1.json"
    out2 = tmp_path / "r2.json"
    b1 = _run_audit_to_bytes(config=config, profile=profile, output=out1)
    b2 = _run_audit_to_bytes(config=config, profile=profile, output=out2)
    assert b1 == b2


# ---------------------------------------------------------------------------
# Regeneration helper (CLI; not a pytest test)
# ---------------------------------------------------------------------------


def _regenerate() -> None:  # pragma: no cover - manual operator path
    """Regenerate every golden baseline.

    Runs the same pipeline as the tests but writes the resulting bytes
    into ``tests/golden/`` so a maintainer can commit the new baseline.
    """
    import unittest.mock as _mock

    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)

    real_run_audit = getattr(audit_cli, "run_audit")  # noqa: B009 - bypass __all__ export check

    def _patched(targets: Any, **kwargs: Any) -> Any:
        kwargs["probe_impl"] = StaticProbe(_CANNED)
        return real_run_audit(targets, **kwargs)

    with _mock.patch.object(audit_cli, "run_audit", _patched):
        for config_name, profile, golden_name in GOLDEN_CASES:
            config = EXAMPLES_DIR / config_name
            out = GOLDEN_DIR / golden_name
            qwashed_main(
                [
                    "audit",
                    "run",
                    str(config),
                    "--profile",
                    profile,
                    "--output",
                    str(out),
                    "--deterministic",
                ]
            )
            sys.stdout.write(f"wrote {out}\n")


if __name__ == "__main__":  # pragma: no cover
    if "--regenerate" in sys.argv[1:]:
        _regenerate()
    else:
        sys.stdout.write("usage: python -m tests.audit.test_golden --regenerate\n")
