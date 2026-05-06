# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""``qwashed vault`` command-line interface.

Subcommands
-----------
* ``qwashed vault init [--path PATH]``
    Create a fresh vault. Prompts for passphrase via ``getpass`` (or
    reads ``QWASHED_VAULT_PASSPHRASE``; never accepted as a CLI arg).
* ``qwashed vault put <file> [--path PATH] [--name NAME]``
    Encrypt a file into the vault and append a signed audit line.
* ``qwashed vault get <ulid> [--path PATH] [--output FILE]``
    Decrypt an entry and write to ``--output`` (or stdout).
* ``qwashed vault list [--path PATH]``
    List every signed entry's metadata (ulid, name, size, created_at).
* ``qwashed vault verify [--path PATH]``
    Walk the manifest, identity, every entry, and the audit-log chain.
* ``qwashed vault upgrade [--path PATH]``
    Re-encrypt legacy v0.1 entries to the current vault format (v0.2).
    Plaintext stays in memory; each migration appends a signed
    audit-log line. Idempotent.
* ``qwashed vault export <ulid> --recipient FP [--path PATH] [--output FILE]``
    Re-encrypt entry to a recipient and emit a self-contained signed
    bundle.
* ``qwashed vault recipients add ...``
* ``qwashed vault recipients list``
    Local address-book operations.

Defaults
--------
* Vault path: ``~/.qwashed`` (overridable via ``--path``).

Passphrase handling
-------------------
The vault's identity-encrypting passphrase is *never* accepted as a CLI
argument (security checklist item 11.5). Order of resolution:

1. Environment variable ``QWASHED_VAULT_PASSPHRASE`` — useful for
   automation; the caller is responsible for protecting it.
2. ``getpass.getpass()`` — interactive prompt with no echo.

Exit codes
----------
* ``0`` -- success.
* ``1`` -- signature / hash-chain / fingerprint verify failure.
* ``2`` -- structural error (bad path, missing file, bad input).
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import sys
from pathlib import Path

from qwashed.core.errors import (
    ConfigurationError,
    QwashedError,
    SchemaValidationError,
    SignatureError,
)
from qwashed.vault.store import (
    Vault,
    init_vault,
    unlock_vault,
)

__all__ = [
    "build_vault_parser",
    "run_vault_subcommand",
]


# ---------------------------------------------------------------------------
# Defaults & helpers
# ---------------------------------------------------------------------------

#: Environment variable that may carry the vault passphrase. Never logged.
PASSPHRASE_ENV_VAR = "QWASHED_VAULT_PASSPHRASE"  # noqa: S105 - env-var name, not a secret


def _default_vault_path() -> Path:
    """Return the default vault root: ``~/.qwashed``.

    Resolved via :func:`Path.expanduser`; absence of ``$HOME`` falls back
    to ``./.qwashed`` rather than raising, so the CLI is usable in
    sandboxed environments.
    """
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    if home:
        return Path(home) / ".qwashed"
    return Path(".qwashed")


def _resolve_path(args: argparse.Namespace) -> Path:
    raw = getattr(args, "path", None)
    return Path(raw) if raw else _default_vault_path()


def _read_passphrase(*, confirm: bool) -> bytes:
    """Read the vault passphrase from env or interactive prompt.

    Parameters
    ----------
    confirm:
        If ``True``, prompt twice and require both inputs to match.
        Used by :command:`init` so a typo doesn't lock the user out of
        their own vault.
    """
    env_val = os.environ.get(PASSPHRASE_ENV_VAR)
    if env_val is not None:
        if not env_val:
            raise ConfigurationError(
                f"{PASSPHRASE_ENV_VAR} is set but empty",
                error_code="vault.cli.empty_env_passphrase",
            )
        return env_val.encode("utf-8")

    if not sys.stdin.isatty():  # pragma: no cover - depends on stdin type
        raise ConfigurationError(
            (f"no passphrase available: stdin is not a TTY and {PASSPHRASE_ENV_VAR} is not set"),
            error_code="vault.cli.no_passphrase_source",
        )

    first = getpass.getpass("Vault passphrase: ")
    if not first:
        raise ConfigurationError(
            "passphrase must not be empty",
            error_code="vault.cli.empty_passphrase",
        )
    if confirm:
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            raise ConfigurationError(
                "passphrase confirmation did not match",
                error_code="vault.cli.passphrase_mismatch",
            )
    return first.encode("utf-8")


def _open_existing(args: argparse.Namespace) -> Vault:
    root = _resolve_path(args)
    passphrase = _read_passphrase(confirm=False)
    return unlock_vault(root, passphrase)


def _emit_error(prefix: str, exc: QwashedError) -> None:
    """Write a single-line error to stderr including the stable error_code."""
    sys.stderr.write(f"{prefix}: {exc} ({exc.error_code})\n")


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def _vault_init(args: argparse.Namespace) -> int:
    """Implement ``qwashed vault init``."""
    root = _resolve_path(args)
    try:
        passphrase = _read_passphrase(confirm=True)
    except QwashedError as exc:
        _emit_error("qwashed vault init", exc)
        return 2

    try:
        vault = init_vault(root, passphrase)
    except QwashedError as exc:
        _emit_error("qwashed vault init", exc)
        return 2

    sys.stdout.write(f"qwashed vault init: created {vault.root}\n")
    return 0


def _vault_put(args: argparse.Namespace) -> int:
    """Implement ``qwashed vault put <file>``."""
    src = Path(args.file)
    if not src.is_file():
        sys.stderr.write(f"qwashed vault put: file not found: {src}\n")
        return 2

    name = args.name if args.name else src.name
    try:
        plaintext = src.read_bytes()
    except OSError as exc:
        sys.stderr.write(f"qwashed vault put: cannot read {src}: {exc}\n")
        return 2

    try:
        vault = _open_existing(args)
    except QwashedError as exc:
        _emit_error("qwashed vault put", exc)
        return 2

    try:
        meta = vault.put(plaintext, name=name)
    except QwashedError as exc:
        _emit_error("qwashed vault put", exc)
        return 2

    sys.stdout.write(f"{meta.ulid} {meta.size} {meta.name}\n")
    return 0


def _vault_get(args: argparse.Namespace) -> int:
    """Implement ``qwashed vault get <ulid>``."""
    try:
        vault = _open_existing(args)
    except QwashedError as exc:
        _emit_error("qwashed vault get", exc)
        return 2

    try:
        plaintext, meta = vault.get(args.ulid)
    except SignatureError as exc:
        _emit_error("qwashed vault get", exc)
        return 1
    except QwashedError as exc:
        _emit_error("qwashed vault get", exc)
        return 2

    if args.output:
        out_path = Path(args.output)
        try:
            out_path.write_bytes(plaintext)
        except OSError as exc:
            sys.stderr.write(f"qwashed vault get: cannot write {out_path}: {exc}\n")
            return 2
        sys.stdout.write(f"{meta.ulid} -> {out_path} ({meta.size} bytes)\n")
    else:
        sys.stdout.buffer.write(plaintext)
    return 0


def _vault_list(args: argparse.Namespace) -> int:
    """Implement ``qwashed vault list``."""
    try:
        vault = _open_existing(args)
    except QwashedError as exc:
        _emit_error("qwashed vault list", exc)
        return 2

    try:
        entries = vault.list()
    except SignatureError as exc:
        _emit_error("qwashed vault list", exc)
        return 1
    except QwashedError as exc:
        _emit_error("qwashed vault list", exc)
        return 2

    for meta in entries:
        sys.stdout.write(f"{meta.ulid}\t{meta.size}\t{meta.created_at}\t{meta.name}\n")
    return 0


def _vault_verify(args: argparse.Namespace) -> int:
    """Implement ``qwashed vault verify``.

    Note: signature / hash-chain failures detected at *unlock* time
    (e.g. a tampered audit-log line — :class:`AuditLogReader` verifies
    the chain in its constructor) are reported as exit code ``1``,
    matching the exit-code semantics of an error caught inside
    :meth:`Vault.verify` itself.
    """
    try:
        vault = _open_existing(args)
    except SignatureError as exc:
        _emit_error("qwashed vault verify", exc)
        return 1
    except QwashedError as exc:
        _emit_error("qwashed vault verify", exc)
        return 2

    try:
        vault.verify()
    except SignatureError as exc:
        _emit_error("qwashed vault verify", exc)
        return 1
    except QwashedError as exc:
        _emit_error("qwashed vault verify", exc)
        return 2

    sys.stdout.write(f"qwashed vault verify: OK ({vault.root})\n")
    return 0


def _vault_upgrade(args: argparse.Namespace) -> int:
    """Implement ``qwashed vault upgrade``.

    Re-encrypts every legacy entry in the vault to the current vault
    format version (v0.2). Plaintext stays in memory; nothing is
    written to disk in cleartext. Each migration is a hybrid-signed
    audit-log line. The command is idempotent: a vault already at the
    current format reports zero entries upgraded.
    """
    try:
        vault = _open_existing(args)
    except SignatureError as exc:
        _emit_error("qwashed vault upgrade", exc)
        return 1
    except QwashedError as exc:
        _emit_error("qwashed vault upgrade", exc)
        return 2

    try:
        report = vault.upgrade()
    except SignatureError as exc:
        _emit_error("qwashed vault upgrade", exc)
        return 1
    except QwashedError as exc:
        _emit_error("qwashed vault upgrade", exc)
        return 2

    sys.stdout.write(
        (
            f"qwashed vault upgrade: {len(report.upgraded)} upgraded, "
            f"{len(report.already_current)} already at v{report.target_format_version} "
            f"({vault.root})\n"
        )
    )
    for ulid in report.upgraded:
        sys.stdout.write(f"  upgraded\t{ulid}\n")
    return 0


def _vault_export(args: argparse.Namespace) -> int:
    """Implement ``qwashed vault export <ulid> --recipient FP``."""
    try:
        vault = _open_existing(args)
    except QwashedError as exc:
        _emit_error("qwashed vault export", exc)
        return 2

    try:
        bundle_bytes = vault.export(args.ulid, args.recipient)
    except SignatureError as exc:
        _emit_error("qwashed vault export", exc)
        return 1
    except QwashedError as exc:
        _emit_error("qwashed vault export", exc)
        return 2

    if args.output:
        out_path = Path(args.output)
        try:
            out_path.write_bytes(bundle_bytes)
        except OSError as exc:
            sys.stderr.write(f"qwashed vault export: cannot write {out_path}: {exc}\n")
            return 2
        sys.stdout.write(f"qwashed vault export: wrote {len(bundle_bytes)} bytes to {out_path}\n")
    else:
        sys.stdout.buffer.write(bundle_bytes)
        sys.stdout.buffer.write(b"\n")
    return 0


# ---- recipients --------------------------------------------------------------


def _read_pubkey_input(arg_path: str | None, arg_b64: str | None, *, label: str) -> bytes:
    """Resolve a pubkey argument: either ``--<label>-pk-file`` or ``--<label>-pk-b64``.

    Exactly one must be supplied. Files may contain either raw bytes or
    base64-encoded text; we try base64 first if decoding succeeds, then
    fall back to raw.
    """
    if (arg_path is None) == (arg_b64 is None):
        raise SchemaValidationError(
            f"exactly one of --{label}-pk-file / --{label}-pk-b64 must be provided",
            error_code="vault.cli.recipient_pk_arg_xor",
        )
    if arg_b64 is not None:
        try:
            return base64.b64decode(arg_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise SchemaValidationError(
                f"--{label}-pk-b64 is not valid base64: {exc}",
                error_code="vault.cli.recipient_bad_b64",
            ) from exc

    # arg_path is non-None here because the XOR check above ruled out
    # the (None, None) case; ruff S101 silenced inline.
    if arg_path is None:  # pragma: no cover - guarded by the XOR above
        raise SchemaValidationError(
            "internal error: arg_path resolution",
            error_code="vault.cli.recipient_pk_internal",
        )
    path = Path(arg_path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigurationError(
            f"cannot read pubkey file {path}: {exc}",
            error_code="vault.cli.recipient_pk_io",
        ) from exc
    # Try base64 (text) first; fall back to raw bytes.
    try:
        text = raw.decode("ascii").strip()
        return base64.b64decode(text, validate=True)
    except (UnicodeDecodeError, ValueError):
        return raw


def _vault_recipients_add(args: argparse.Namespace) -> int:
    """Implement ``qwashed vault recipients add``."""
    try:
        kem_pk = _read_pubkey_input(args.kem_pk_file, args.kem_pk_b64, label="kem")
        sig_pk = _read_pubkey_input(args.sig_pk_file, args.sig_pk_b64, label="sig")
    except QwashedError as exc:
        _emit_error("qwashed vault recipients add", exc)
        return 2

    try:
        vault = _open_existing(args)
    except QwashedError as exc:
        _emit_error("qwashed vault recipients add", exc)
        return 2

    try:
        recipient = vault.add_recipient(kem_pk=kem_pk, sig_pk=sig_pk, label=args.label)
    except QwashedError as exc:
        _emit_error("qwashed vault recipients add", exc)
        return 2

    sys.stdout.write(f"{recipient.fingerprint}\t{recipient.label}\n")
    return 0


def _vault_recipients_list(args: argparse.Namespace) -> int:
    """Implement ``qwashed vault recipients list``."""
    try:
        vault = _open_existing(args)
    except QwashedError as exc:
        _emit_error("qwashed vault recipients list", exc)
        return 2

    try:
        recipients = vault.list_recipients()
    except SignatureError as exc:
        _emit_error("qwashed vault recipients list", exc)
        return 1
    except QwashedError as exc:
        _emit_error("qwashed vault recipients list", exc)
        return 2

    for r in recipients:
        sys.stdout.write(f"{r.fingerprint}\t{r.added_at}\t{r.label}\n")
    return 0


# ---------------------------------------------------------------------------
# Argparse wiring
# ---------------------------------------------------------------------------


def _add_path_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--path",
        default=None,
        help="path to the vault root (default: ~/.qwashed)",
    )


def build_vault_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Attach the ``vault`` subcommand tree to a top-level parser.

    Caller (``qwashed.cli``) provides the ``subparsers`` object returned
    by :meth:`argparse.ArgumentParser.add_subparsers`.
    """
    vault_parser = subparsers.add_parser(
        "vault",
        help="hybrid post-quantum vault: local-only encrypted file/message store",
        description=(
            "Local-only hybrid-encrypted (X25519 || ML-KEM-768) and "
            "hybrid-signed (Ed25519 || ML-DSA-65) file/message store with a "
            "tamper-evident, hash-chained audit log."
        ),
    )
    vault_subs = vault_parser.add_subparsers(
        dest="vault_command",
        metavar="{init,put,get,list,verify,upgrade,export,recipients}",
        required=False,
    )

    # init
    init_p = vault_subs.add_parser(
        "init",
        help="initialize a fresh vault",
        description="Create a new vault root and a fresh hybrid identity.",
    )
    _add_path_arg(init_p)
    init_p.set_defaults(func=_vault_init)

    # put
    put_p = vault_subs.add_parser(
        "put",
        help="encrypt a file into the vault",
        description="Encrypt FILE into the vault and emit its ULID on stdout.",
    )
    _add_path_arg(put_p)
    put_p.add_argument("file", help="path to the plaintext file to ingest")
    put_p.add_argument(
        "--name",
        default=None,
        help="logical name for the entry (default: source filename)",
    )
    put_p.set_defaults(func=_vault_put)

    # get
    get_p = vault_subs.add_parser(
        "get",
        help="decrypt an entry by ULID",
        description="Decrypt the entry identified by ULID.",
    )
    _add_path_arg(get_p)
    get_p.add_argument("ulid", help="ULID of the entry to decrypt")
    get_p.add_argument(
        "--output",
        "-o",
        default=None,
        help="destination file (default: stdout)",
    )
    get_p.set_defaults(func=_vault_get)

    # list
    list_p = vault_subs.add_parser(
        "list",
        help="list every entry in the vault",
        description="List ulid, size, created_at, and name of every entry.",
    )
    _add_path_arg(list_p)
    list_p.set_defaults(func=_vault_list)

    # verify
    verify_p = vault_subs.add_parser(
        "verify",
        help="walk the vault and verify every signature + audit chain",
        description=(
            "Verify the manifest signature, every entry's signed metadata, "
            "every entry's blob hash, and the full hash-chained audit log."
        ),
    )
    _add_path_arg(verify_p)
    verify_p.set_defaults(func=_vault_verify)

    # upgrade
    upgrade_p = vault_subs.add_parser(
        "upgrade",
        help="re-encrypt legacy v0.1 entries to the current vault format",
        description=(
            "Walk every entry in the vault, decrypt in memory, and "
            "re-encrypt to the current vault format (v0.2). Each "
            "migration appends a hybrid-signed audit-log line. The "
            "operation is idempotent: a vault already at the current "
            "format reports zero entries upgraded."
        ),
    )
    _add_path_arg(upgrade_p)
    upgrade_p.set_defaults(func=_vault_upgrade)

    # export
    export_p = vault_subs.add_parser(
        "export",
        help="re-encrypt an entry to a recipient",
        description=(
            "Re-encrypt entry ULID under the named recipient's hybrid KEM "
            "public key and emit a self-contained, signed bundle."
        ),
    )
    _add_path_arg(export_p)
    export_p.add_argument("ulid", help="ULID of the entry to export")
    export_p.add_argument(
        "--recipient",
        required=True,
        help="recipient fingerprint (32-char lowercase hex)",
    )
    export_p.add_argument(
        "--output",
        "-o",
        default=None,
        help="path for the export bundle JSON (default: stdout)",
    )
    export_p.set_defaults(func=_vault_export)

    # recipients
    recip_p = vault_subs.add_parser(
        "recipients",
        help="manage the local recipient address book",
        description="Add or list local recipient pubkey entries.",
    )
    recip_subs = recip_p.add_subparsers(
        dest="recipients_command",
        metavar="{add,list}",
        required=False,
    )

    add_p = recip_subs.add_parser(
        "add",
        help="add a recipient pubkey",
        description=(
            "Register a recipient by their hybrid KEM and SIG public keys. "
            "Provide each key via --<kem|sig>-pk-file (raw bytes or base64) "
            "or --<kem|sig>-pk-b64 (inline base64). Exactly one form per key."
        ),
    )
    _add_path_arg(add_p)
    add_p.add_argument("--label", required=True, help="human-friendly label")
    add_p.add_argument("--kem-pk-file", default=None, help="path to KEM pubkey")
    add_p.add_argument("--kem-pk-b64", default=None, help="inline base64 KEM pubkey")
    add_p.add_argument("--sig-pk-file", default=None, help="path to SIG pubkey")
    add_p.add_argument("--sig-pk-b64", default=None, help="inline base64 SIG pubkey")
    add_p.set_defaults(func=_vault_recipients_add)

    list_recip_p = recip_subs.add_parser(
        "list",
        help="list local recipient address-book entries",
        description="List every <fingerprint>.pub recipient on disk.",
    )
    _add_path_arg(list_recip_p)
    list_recip_p.set_defaults(func=_vault_recipients_list)

    def _recip_help(args: argparse.Namespace) -> int:
        del args
        recip_p.print_help(sys.stderr)
        return 2

    recip_p.set_defaults(func=_recip_help)

    def _vault_help(args: argparse.Namespace) -> int:
        del args
        vault_parser.print_help(sys.stderr)
        return 2

    vault_parser.set_defaults(func=_vault_help)


def run_vault_subcommand(args: argparse.Namespace) -> int:
    """Top-level dispatch entry; ``qwashed.cli`` wires this in."""
    func = getattr(args, "func", None)
    if func is None:  # pragma: no cover - argparse always sets one
        sys.stderr.write("qwashed vault: no handler bound\n")
        return 2
    return int(func(args))
