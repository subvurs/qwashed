# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Integration tests for the ``qwashed audit`` subcommand.

These tests stub the network probe (StdlibTlsProbe) with a StaticProbe
so the CLI runs deterministically without touching any host. They cover
the user-visible round trip:

* `qwashed audit run --deterministic ...` -> signed JSON artifact
* `qwashed verify <artifact>` -> exit code 0
* `--deterministic` -> bit-identical bytes across two runs
* `qwashed audit profiles` lists the bundled threat profiles.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from qwashed.audit import cli as audit_cli
from qwashed.audit.probe import StaticProbe
from qwashed.audit.schemas import AuditTarget, ProbeResult
from qwashed.cli import main as qwashed_main


def _classical_canned() -> dict[tuple[str, int], ProbeResult]:
    target = AuditTarget(host="x.example", port=443)
    return {
        ("x.example", 443): ProbeResult(
            target=target,
            status="ok",
            negotiated_protocol_version="TLSv1.3",
            cipher_suite="TLS_AES_128_GCM_SHA256",
            key_exchange_group="X25519",
            signature_algorithm="rsa_pss_rsae_sha256",
        ),
    }


def _hybrid_canned() -> dict[tuple[str, int], ProbeResult]:
    target = AuditTarget(host="y.example", port=443)
    return {
        ("y.example", 443): ProbeResult(
            target=target,
            status="ok",
            negotiated_protocol_version="TLSv1.3",
            cipher_suite="TLS_AES_128_GCM_SHA256",
            key_exchange_group="X25519MLKEM768",
            signature_algorithm="ed25519",
        ),
    }


@pytest.fixture
def static_probe_classical(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch ``run_audit`` inside the CLI to inject a classical StaticProbe."""
    real_run_audit = getattr(audit_cli, "run_audit")  # noqa: B009 - bypass __all__ export check

    def _patched(targets: Any, **kwargs: Any) -> Any:
        kwargs["probe_impl"] = StaticProbe(_classical_canned())
        return real_run_audit(targets, **kwargs)

    monkeypatch.setattr(audit_cli, "run_audit", _patched)


@pytest.fixture
def static_probe_hybrid(monkeypatch: pytest.MonkeyPatch) -> None:
    real_run_audit = getattr(audit_cli, "run_audit")  # noqa: B009 - bypass __all__ export check

    def _patched(targets: Any, **kwargs: Any) -> Any:
        kwargs["probe_impl"] = StaticProbe(_hybrid_canned())
        return real_run_audit(targets, **kwargs)

    monkeypatch.setattr(audit_cli, "run_audit", _patched)


def _write_config(tmp_path: Path, host: str, port: int) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"targets:\n  - host: {host}\n    port: {port}\n",
        encoding="utf-8",
    )
    return cfg


class TestAuditRun:
    def test_run_writes_signed_json(
        self,
        tmp_path: Path,
        static_probe_classical: None,
    ) -> None:
        cfg = _write_config(tmp_path, "x.example", 443)
        out = tmp_path / "report.json"
        rc = qwashed_main(
            [
                "audit",
                "run",
                str(cfg),
                "--profile",
                "default",
                "--output",
                str(out),
                "--deterministic",
            ]
        )
        assert rc in (0, 1)  # 1 only if classical X25519 -> critical under default
        doc = json.loads(out.read_bytes())
        assert "signature_ed25519" in doc
        assert "ed25519_pubkey" in doc
        assert doc["generated_at"] == "2026-01-01T00:00:00Z"
        assert doc["qwashed_version"] == "0.1.0"
        assert len(doc["findings"]) == 1
        assert doc["findings"][0]["category"] == "classical"

    def test_deterministic_run_is_byte_stable(
        self,
        tmp_path: Path,
        static_probe_classical: None,
    ) -> None:
        cfg = _write_config(tmp_path, "x.example", 443)
        out1 = tmp_path / "r1.json"
        out2 = tmp_path / "r2.json"
        for out in (out1, out2):
            qwashed_main(
                [
                    "audit",
                    "run",
                    str(cfg),
                    "--output",
                    str(out),
                    "--deterministic",
                ]
            )
        assert out1.read_bytes() == out2.read_bytes()

    def test_artifact_round_trips_through_verify(
        self,
        tmp_path: Path,
        static_probe_classical: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        cfg = _write_config(tmp_path, "x.example", 443)
        out = tmp_path / "report.json"
        qwashed_main(
            [
                "audit",
                "run",
                str(cfg),
                "--output",
                str(out),
                "--deterministic",
            ]
        )
        capsys.readouterr()  # discard audit output
        rc = qwashed_main(["verify", str(out)])
        captured = capsys.readouterr()
        assert rc == 0, f"verify failed: {captured.err}"
        assert "OK" in captured.out

    def test_html_render_produced(
        self,
        tmp_path: Path,
        static_probe_hybrid: None,
    ) -> None:
        cfg = _write_config(tmp_path, "y.example", 443)
        out = tmp_path / "report.json"
        html = tmp_path / "report.html"
        rc = qwashed_main(
            [
                "audit",
                "run",
                str(cfg),
                "--output",
                str(out),
                "--html",
                str(html),
                "--deterministic",
            ]
        )
        assert rc == 0  # hybrid finding is not critical
        body = html.read_text(encoding="utf-8")
        assert body.startswith("<!DOCTYPE html>")
        assert "y.example:443" in body

    def test_missing_config_returns_2(self, tmp_path: Path) -> None:
        rc = qwashed_main(
            [
                "audit",
                "run",
                str(tmp_path / "does-not-exist.yaml"),
                "--deterministic",
            ]
        )
        assert rc == 2

    def test_unknown_profile_returns_2(
        self,
        tmp_path: Path,
        static_probe_classical: None,
    ) -> None:
        cfg = _write_config(tmp_path, "x.example", 443)
        rc = qwashed_main(
            [
                "audit",
                "run",
                str(cfg),
                "--profile",
                "no-such-profile-xyz",
                "--deterministic",
            ]
        )
        assert rc == 2


class TestAuditProfiles:
    def test_lists_bundled_profiles(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = qwashed_main(["audit", "profiles"])
        assert rc == 0
        out = capsys.readouterr().out
        # Each bundled profile should show up by name.
        for name in ("default", "healthcare", "journalism", "legal"):
            assert name in out
