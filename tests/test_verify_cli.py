# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Integration tests for `qwashed verify`."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from qwashed.cli import main
from qwashed.core.canonical import canonicalize
from qwashed.core.signing import SigningKey


def _build_signed_artifact(payload: dict[str, object], sk: SigningKey) -> dict[str, object]:
    """Build a Qwashed signed artifact in the format `qwashed verify` expects."""
    doc = dict(payload)
    doc["ed25519_pubkey"] = sk.verify_key.to_b64()
    payload_canonical = canonicalize(doc)
    sig = sk.sign(payload_canonical)
    doc["signature_ed25519"] = base64.b64encode(sig).decode("ascii")
    return doc


class TestVerifyCli:
    def test_valid_artifact_returns_zero(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        sk = SigningKey.generate()
        doc = _build_signed_artifact({"version": "0.1", "data": "hello"}, sk)
        artifact = tmp_path / "artifact.json"
        artifact.write_text(json.dumps(doc))

        rc = main(["verify", str(artifact)])

        assert rc == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_tampered_payload_returns_one(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        sk = SigningKey.generate()
        doc = _build_signed_artifact({"version": "0.1", "data": "hello"}, sk)
        # Tamper with the payload AFTER signing.
        doc["data"] = "EVIL"
        artifact = tmp_path / "artifact.json"
        artifact.write_text(json.dumps(doc))

        rc = main(["verify", str(artifact)])

        assert rc == 1
        captured = capsys.readouterr()
        assert "MISMATCH" in captured.err

    def test_missing_file_returns_two(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        rc = main(["verify", str(tmp_path / "does-not-exist.json")])
        assert rc == 2
        captured = capsys.readouterr()
        assert "cannot read" in captured.err

    def test_invalid_json_returns_two(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        artifact = tmp_path / "artifact.json"
        artifact.write_text("not json")
        rc = main(["verify", str(artifact)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "invalid JSON" in captured.err

    def test_missing_signature_field_returns_two(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        artifact = tmp_path / "artifact.json"
        artifact.write_text(json.dumps({"version": "0.1"}))
        rc = main(["verify", str(artifact)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "missing required fields" in captured.err

    def test_top_level_array_rejected(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        artifact = tmp_path / "artifact.json"
        artifact.write_text(json.dumps([1, 2, 3]))
        rc = main(["verify", str(artifact)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "top-level JSON" in captured.err

    def test_malformed_signature_returns_two(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        sk = SigningKey.generate()
        doc = {
            "version": "0.1",
            "ed25519_pubkey": sk.verify_key.to_b64(),
            "signature_ed25519": "not-base64@@@",
        }
        artifact = tmp_path / "artifact.json"
        artifact.write_text(json.dumps(doc))
        rc = main(["verify", str(artifact)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "malformed key or signature" in captured.err
