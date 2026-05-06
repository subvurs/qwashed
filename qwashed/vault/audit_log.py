# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Append-only, hash-chained, hybrid-signed audit log.

Every vault-mutating operation (init, put, get, delete, export, upgrade)
writes a single line to the vault's ``audit_log.jsonl`` file. Each line is:

* a canonical JSON object,
* hash-chained to the previous line via SHA3-256 of the canonicalized
  prior payload,
* hybrid-signed (Ed25519 || ML-DSA-65) by the vault owner's identity
  key over the chain hash + the line's own canonical body,
* never modified after write -- only appended.

Wire format (one line per entry, JSONL)::

    {
      "ts":         "2026-04-30T17:00:00Z",   # RFC 3339 UTC
      "op":         "put",                    # one of OPS
      "subject":    "<entry-ulid>",           # subject of the operation
      "actor_pk":   "<base64 hybrid public key envelope>",
      "prev_hash":  "<hex sha3-256 of previous line's canonical body>",
      "sig_hybrid": "<base64 hybrid sig envelope over canonical body+chain>"
    }

The genesis line uses ``prev_hash = "0" * 64`` and an op of ``"init"``.

Verification (:func:`verify_chain`):

#. Each line's ``prev_hash`` must equal SHA3-256(canonical body of
   previous line, with ``sig_hybrid`` removed).
#. Each line's ``sig_hybrid`` must verify under ``actor_pk`` over
   ``prev_hash || canonical body of the line minus sig_hybrid``.
#. Any failure raises :class:`SignatureError` with a stable error_code
   and the offending line index.

This is fail-closed: a tampered line breaks the chain at *that* line and
every line after it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal

from qwashed.core.canonical import canonicalize
from qwashed.core.errors import SchemaValidationError, SignatureError
from qwashed.vault.hybrid_sig import HybridSigKeypair, sign, verify

__all__ = [
    "GENESIS_PREV_HASH",
    "OPS",
    "AuditLogEntry",
    "AuditLogReader",
    "AuditLogWriter",
    "append_entry",
    "canonical_body",
    "verify_chain",
]

#: All operations the vault may record.
OPS: Final[frozenset[str]] = frozenset({"init", "put", "get", "delete", "export", "upgrade"})

#: Sentinel ``prev_hash`` for the genesis line.
GENESIS_PREV_HASH: Final[str] = "0" * 64


# ---------------------------------------------------------------------------
# Entry shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditLogEntry:
    """One audit-log line, parsed.

    The signature is the hybrid Ed25519 || ML-DSA-65 envelope produced
    by :func:`qwashed.vault.hybrid_sig.sign`. ``actor_pk`` is the same
    hybrid public key envelope.
    """

    ts: str
    op: Literal["init", "put", "get", "delete", "export", "upgrade"]
    subject: str
    actor_pk_b64: str
    prev_hash: str
    sig_hybrid_b64: str

    def to_dict(self, *, with_signature: bool = True) -> dict[str, Any]:
        """Return the dict form. ``with_signature=False`` omits ``sig_hybrid``
        for canonicalization-before-signing.
        """
        out: dict[str, Any] = {
            "actor_pk": self.actor_pk_b64,
            "op": self.op,
            "prev_hash": self.prev_hash,
            "subject": self.subject,
            "ts": self.ts,
        }
        if with_signature:
            out["sig_hybrid"] = self.sig_hybrid_b64
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_op(op: str) -> Literal["init", "put", "get", "delete", "export", "upgrade"]:
    if op not in OPS:
        raise SchemaValidationError(
            f"audit log op must be one of {sorted(OPS)}, got {op!r}",
            error_code="vault.audit.bad_op",
        )
    return op  # type: ignore[return-value]


def canonical_body(entry: AuditLogEntry) -> bytes:
    """Return the canonical JSON bytes of ``entry`` *without* the signature.

    This is the exact preimage hashed for ``prev_hash`` of the next line.
    """
    return canonicalize(entry.to_dict(with_signature=False))


def _signing_preimage(prev_hash_hex: str, body: bytes) -> bytes:
    """Build the signature preimage: prev_hash bytes || canonical body."""
    try:
        prev_bytes = bytes.fromhex(prev_hash_hex)
    except ValueError as exc:
        raise SignatureError(
            f"prev_hash is not valid hex: {prev_hash_hex!r}",
            error_code="vault.audit.bad_prev_hash",
        ) from exc
    if len(prev_bytes) != 32:
        raise SignatureError(
            f"prev_hash must decode to 32 bytes, got {len(prev_bytes)}",
            error_code="vault.audit.bad_prev_hash_length",
        )
    return prev_bytes + body


def _utc_now_iso() -> str:
    # Drop microseconds; canonical RFC 3339 with Z suffix.
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Append
# ---------------------------------------------------------------------------


def append_entry(
    log_path: Path,
    *,
    op: str,
    subject: str,
    actor: HybridSigKeypair,
    prev_hash: str,
    ts: str | None = None,
) -> AuditLogEntry:
    """Sign and append a new audit log entry to ``log_path``.

    The caller is responsible for supplying ``prev_hash`` -- typically
    the SHA3-256 of the previous line's canonical body, or
    :data:`GENESIS_PREV_HASH` for the first ("init") line.

    Parameters
    ----------
    log_path:
        Path to the JSONL audit log file. Created if missing.
    op:
        One of :data:`OPS`.
    subject:
        Identifier of the operation's target (e.g. entry ULID, vault
        path). Must be non-empty.
    actor:
        :class:`HybridSigKeypair` of the vault owner. Used to sign.
    prev_hash:
        Hex SHA3-256 of the previous line's canonical body, or
        :data:`GENESIS_PREV_HASH` for the genesis line.
    ts:
        Optional override for the timestamp (used by golden tests).
        Defaults to current UTC.

    Returns
    -------
    AuditLogEntry
        The freshly written entry, exactly as committed to disk.

    Raises
    ------
    SchemaValidationError
        On unknown op or empty subject.
    SignatureError
        On malformed ``prev_hash`` or signing failure.
    """
    op_lit = _validate_op(op)
    if not subject:
        raise SchemaValidationError(
            "audit log subject must not be empty",
            error_code="vault.audit.empty_subject",
        )

    actor_pk_b64 = base64.b64encode(actor.public_bytes()).decode("ascii")
    timestamp = ts if ts is not None else _utc_now_iso()

    unsigned = AuditLogEntry(
        ts=timestamp,
        op=op_lit,
        subject=subject,
        actor_pk_b64=actor_pk_b64,
        prev_hash=prev_hash,
        sig_hybrid_b64="",  # filled below
    )
    body = canonical_body(unsigned)
    preimage = _signing_preimage(prev_hash, body)
    sig_blob = sign(actor, preimage)
    sig_b64 = base64.b64encode(sig_blob).decode("ascii")

    final = AuditLogEntry(
        ts=timestamp,
        op=op_lit,
        subject=subject,
        actor_pk_b64=actor_pk_b64,
        prev_hash=prev_hash,
        sig_hybrid_b64=sig_b64,
    )

    # Append: open in append mode, write canonical bytes + newline.
    line_bytes = canonicalize(final.to_dict(with_signature=True)) + b"\n"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("ab") as fh:
        fh.write(line_bytes)

    return final


# ---------------------------------------------------------------------------
# Read + verify
# ---------------------------------------------------------------------------


def _parse_line(idx: int, raw: bytes) -> AuditLogEntry:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SchemaValidationError(
            f"audit log line {idx} is not valid UTF-8 JSON: {exc}",
            error_code="vault.audit.bad_line",
        ) from exc
    required = {"ts", "op", "subject", "actor_pk", "prev_hash", "sig_hybrid"}
    missing = sorted(required - doc.keys())
    if missing:
        raise SchemaValidationError(
            f"audit log line {idx} missing keys: {missing}",
            error_code="vault.audit.missing_keys",
        )
    extras = sorted(doc.keys() - required)
    if extras:
        raise SchemaValidationError(
            f"audit log line {idx} has unknown keys: {extras}",
            error_code="vault.audit.unknown_keys",
        )
    return AuditLogEntry(
        ts=str(doc["ts"]),
        op=_validate_op(str(doc["op"])),
        subject=str(doc["subject"]),
        actor_pk_b64=str(doc["actor_pk"]),
        prev_hash=str(doc["prev_hash"]),
        sig_hybrid_b64=str(doc["sig_hybrid"]),
    )


def verify_chain(log_path: Path) -> list[AuditLogEntry]:
    """Verify hash chain + every hybrid signature in ``log_path``.

    Returns
    -------
    list[AuditLogEntry]
        Parsed entries in file order.

    Raises
    ------
    SchemaValidationError
        On malformed JSON or missing keys.
    SignatureError
        On chain mismatch, signature verification failure, or malformed
        component.
    """
    if not log_path.is_file():
        raise SignatureError(
            f"audit log file does not exist: {log_path}",
            error_code="vault.audit.missing_log",
        )

    entries: list[AuditLogEntry] = []
    expected_prev = GENESIS_PREV_HASH

    with log_path.open("rb") as fh:
        for idx, raw_line in enumerate(fh):
            stripped = raw_line.rstrip(b"\n")
            if not stripped:
                continue
            entry = _parse_line(idx, stripped)

            # Chain check.
            if entry.prev_hash != expected_prev:
                raise SignatureError(
                    f"audit log line {idx} prev_hash mismatch: "
                    f"expected {expected_prev}, got {entry.prev_hash}",
                    error_code="vault.audit.chain_break",
                )

            # Signature check.
            try:
                actor_pk = base64.b64decode(entry.actor_pk_b64, validate=True)
                sig = base64.b64decode(entry.sig_hybrid_b64, validate=True)
            except Exception as exc:
                raise SignatureError(
                    f"audit log line {idx} has invalid base64 fields: {exc}",
                    error_code="vault.audit.bad_b64",
                ) from exc
            body = canonical_body(entry)
            preimage = _signing_preimage(entry.prev_hash, body)
            ok = verify(actor_pk, preimage, sig)
            if not ok:
                raise SignatureError(
                    f"audit log line {idx} signature failed AND-verify",
                    error_code="vault.audit.bad_signature",
                )

            entries.append(entry)
            digest = hashlib.sha3_256(body).hexdigest()
            expected_prev = digest

    return entries


# ---------------------------------------------------------------------------
# High-level convenience helpers
# ---------------------------------------------------------------------------


class AuditLogReader:
    """Read-only iterator over verified audit log entries.

    Wraps :func:`verify_chain` so callers can iterate without re-running
    verification per entry.
    """

    def __init__(self, log_path: Path) -> None:
        self._entries: list[AuditLogEntry] = verify_chain(log_path)

    def __iter__(self) -> Iterator[AuditLogEntry]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def latest(self) -> AuditLogEntry | None:
        return self._entries[-1] if self._entries else None


class AuditLogWriter:
    """Stateful append helper that tracks the running ``prev_hash``.

    Use this when emitting several lines in sequence (e.g., during a
    multi-step CLI command). Reads existing log on construction, then
    each :meth:`append` updates the running chain hash in memory.
    """

    def __init__(self, log_path: Path, actor: HybridSigKeypair) -> None:
        self._log_path = log_path
        self._actor = actor
        if log_path.exists() and log_path.stat().st_size > 0:
            entries = verify_chain(log_path)
            last = entries[-1]
            self._prev_hash: str = hashlib.sha3_256(canonical_body(last)).hexdigest()
        else:
            self._prev_hash = GENESIS_PREV_HASH

    @property
    def prev_hash(self) -> str:
        return self._prev_hash

    def append(
        self,
        *,
        op: str,
        subject: str,
        ts: str | None = None,
    ) -> AuditLogEntry:
        entry = append_entry(
            self._log_path,
            op=op,
            subject=subject,
            actor=self._actor,
            prev_hash=self._prev_hash,
            ts=ts,
        )
        self._prev_hash = hashlib.sha3_256(canonical_body(entry)).hexdigest()
        return entry
