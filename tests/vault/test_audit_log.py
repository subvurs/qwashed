# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.vault.audit_log.

Covers:

* Genesis line uses ``prev_hash = GENESIS_PREV_HASH``.
* Hash chain links every line to the SHA3-256 of the prior canonical
  body.
* Every line is hybrid-signed and AND-verifies under the recorded
  ``actor_pk``.
* Tampering ANY field of ANY line breaks the chain at that line and
  every line after it (fail-closed).
* Replacing a line entirely with a different signed line (different
  actor) is detected.
* Bad ``op`` / empty subject rejected by writer.
* :class:`AuditLogWriter` correctly resumes after restart, seeing the
  prior chain head.
"""

from __future__ import annotations

import hashlib
import json
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings(
    "ignore",
    message=r"liboqs version .* differs",
    category=UserWarning,
)

from qwashed.core.canonical import canonicalize  # noqa: E402
from qwashed.core.errors import SchemaValidationError, SignatureError  # noqa: E402
from qwashed.vault.audit_log import (  # noqa: E402
    GENESIS_PREV_HASH,
    AuditLogReader,
    AuditLogWriter,
    append_entry,
    canonical_body,
    verify_chain,
)
from qwashed.vault.hybrid_sig import generate_keypair  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_lines(p: Path) -> list[bytes]:
    with p.open("rb") as fh:
        return [line.rstrip(b"\n") for line in fh if line.strip()]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAppend:
    def test_genesis_line(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        actor = generate_keypair()
        entry = append_entry(
            log,
            op="init",
            subject="vault://example",
            actor=actor,
            prev_hash=GENESIS_PREV_HASH,
            ts="2026-04-30T17:00:00Z",
        )
        assert entry.prev_hash == GENESIS_PREV_HASH
        assert log.is_file()
        lines = _read_lines(log)
        assert len(lines) == 1
        # Verify the chain end-to-end.
        verified = verify_chain(log)
        assert len(verified) == 1
        assert verified[0].op == "init"

    def test_two_line_chain(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        actor = generate_keypair()
        first = append_entry(
            log,
            op="init",
            subject="vault://example",
            actor=actor,
            prev_hash=GENESIS_PREV_HASH,
        )
        second_prev = hashlib.sha3_256(canonical_body(first)).hexdigest()
        append_entry(
            log,
            op="put",
            subject="01HZX1234567890ABCDEFGHJKL",
            actor=actor,
            prev_hash=second_prev,
        )
        verified = verify_chain(log)
        assert len(verified) == 2
        assert verified[1].prev_hash == second_prev


class TestWriter:
    def test_writer_threads_chain(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        actor = generate_keypair()
        w = AuditLogWriter(log, actor)
        assert w.prev_hash == GENESIS_PREV_HASH
        w.append(op="init", subject="vault://x")
        w.append(op="put", subject="01HENTRY1")
        w.append(op="put", subject="01HENTRY2")
        verified = verify_chain(log)
        assert len(verified) == 3
        # Chain is linear.
        assert verified[0].prev_hash == GENESIS_PREV_HASH
        assert verified[1].prev_hash == hashlib.sha3_256(canonical_body(verified[0])).hexdigest()
        assert verified[2].prev_hash == hashlib.sha3_256(canonical_body(verified[1])).hexdigest()

    def test_writer_resumes_after_restart(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        actor = generate_keypair()
        w1 = AuditLogWriter(log, actor)
        w1.append(op="init", subject="vault://x")
        w1.append(op="put", subject="01HENTRY1")
        prev_at_close = w1.prev_hash
        # Simulate process restart with same key.
        w2 = AuditLogWriter(log, actor)
        assert w2.prev_hash == prev_at_close
        w2.append(op="put", subject="01HENTRY2")
        verified = verify_chain(log)
        assert len(verified) == 3


class TestRejectionAtAppend:
    def test_unknown_op_rejected(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        actor = generate_keypair()
        with pytest.raises(SchemaValidationError):
            append_entry(
                log,
                op="evict",  # not in OPS
                subject="x",
                actor=actor,
                prev_hash=GENESIS_PREV_HASH,
            )

    def test_empty_subject_rejected(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        actor = generate_keypair()
        with pytest.raises(SchemaValidationError):
            append_entry(
                log,
                op="put",
                subject="",
                actor=actor,
                prev_hash=GENESIS_PREV_HASH,
            )

    def test_malformed_prev_hash_rejected(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        actor = generate_keypair()
        with pytest.raises(SignatureError):
            append_entry(
                log,
                op="init",
                subject="x",
                actor=actor,
                prev_hash="not-hex-at-all",
            )


class TestTamperDetection:
    def _build_three_line_log(self, tmp_path: Path) -> tuple[Path, object]:
        log = tmp_path / "audit.jsonl"
        actor = generate_keypair()
        w = AuditLogWriter(log, actor)
        w.append(op="init", subject="vault://x")
        w.append(op="put", subject="01HENTRY1")
        w.append(op="put", subject="01HENTRY2")
        return log, actor

    def test_subject_tamper_breaks_chain(self, tmp_path: Path) -> None:
        log, _ = self._build_three_line_log(tmp_path)
        lines = _read_lines(log)
        # Mutate the subject of line 1 (index 1).
        doc = json.loads(lines[1].decode())
        doc["subject"] = "TAMPERED"
        lines[1] = canonicalize(doc)
        log.write_bytes(b"\n".join(lines) + b"\n")
        with pytest.raises(SignatureError):
            verify_chain(log)

    def test_signature_tamper_breaks_chain(self, tmp_path: Path) -> None:
        log, _ = self._build_three_line_log(tmp_path)
        lines = _read_lines(log)
        doc = json.loads(lines[2].decode())
        # Flip a single base64 character of the sig.
        sig = doc["sig_hybrid"]
        flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
        doc["sig_hybrid"] = flipped
        lines[2] = canonicalize(doc)
        log.write_bytes(b"\n".join(lines) + b"\n")
        with pytest.raises(SignatureError):
            verify_chain(log)

    def test_prev_hash_tamper_breaks_chain(self, tmp_path: Path) -> None:
        log, _ = self._build_three_line_log(tmp_path)
        lines = _read_lines(log)
        doc = json.loads(lines[1].decode())
        doc["prev_hash"] = "f" * 64
        lines[1] = canonicalize(doc)
        log.write_bytes(b"\n".join(lines) + b"\n")
        with pytest.raises(SignatureError):
            verify_chain(log)

    def test_swapping_actor_pk_breaks_signature(self, tmp_path: Path) -> None:
        log, _ = self._build_three_line_log(tmp_path)
        lines = _read_lines(log)
        # Replace actor_pk on line 0 with a different generated keypair's
        # pubkey envelope; signature verifies against actor_pk, so it
        # must now fail.
        import base64

        from qwashed.vault.hybrid_sig import generate_keypair as _gen

        evil_pk = base64.b64encode(_gen().public_bytes()).decode("ascii")
        doc = json.loads(lines[0].decode())
        doc["actor_pk"] = evil_pk
        lines[0] = canonicalize(doc)
        log.write_bytes(b"\n".join(lines) + b"\n")
        with pytest.raises(SignatureError):
            verify_chain(log)

    def test_truncated_log_still_verifies_prefix(self, tmp_path: Path) -> None:
        # Truncating the file at a complete line boundary should still
        # verify, just shorter.
        log, _ = self._build_three_line_log(tmp_path)
        lines = _read_lines(log)
        log.write_bytes(b"\n".join(lines[:2]) + b"\n")
        verified = verify_chain(log)
        assert len(verified) == 2

    def test_partial_line_rejected(self, tmp_path: Path) -> None:
        log, _ = self._build_three_line_log(tmp_path)
        with log.open("ab") as fh:
            fh.write(b'{"ts":"partial')  # garbage trailing fragment
        with pytest.raises(SchemaValidationError):
            verify_chain(log)


class TestReader:
    def test_reader_iterates(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        actor = generate_keypair()
        w = AuditLogWriter(log, actor)
        w.append(op="init", subject="vault://x")
        w.append(op="put", subject="01HENTRY1")
        r = AuditLogReader(log)
        assert len(r) == 2
        ops = [e.op for e in r]
        assert ops == ["init", "put"]
        latest = r.latest()
        assert latest is not None
        assert latest.op == "put"

    def test_reader_on_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(SignatureError):
            AuditLogReader(tmp_path / "no-such.jsonl")
