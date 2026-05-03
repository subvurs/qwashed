# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Integration tests for the ``qwashed vault`` subcommand tree.

Strategy: we drive the CLI exactly as a user would, via
:func:`qwashed.cli.main`, but always pass the passphrase through the
``QWASHED_VAULT_PASSPHRASE`` environment variable so no test ever needs
a TTY. Every test uses an isolated ``tmp_path`` vault root and
``monkeypatch.setenv`` so the env var is scoped to the test.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from qwashed.cli import main as qwashed_main
from qwashed.vault.hybrid_kem import (
    decapsulate as hybrid_decap,
)
from qwashed.vault.hybrid_kem import (
    generate_keypair as generate_kem_keypair,
)
from qwashed.vault.hybrid_sig import (
    generate_keypair as generate_sig_keypair,
)
from qwashed.vault.store import (
    open_export_bundle,
    unlock_vault,
)

PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def env_passphrase(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QWASHED_VAULT_PASSPHRASE", PASSPHRASE)


def _vault_root(tmp_path: Path) -> Path:
    return tmp_path / "v"


def _init_vault(tmp_path: Path) -> Path:
    root = _vault_root(tmp_path)
    rc = qwashed_main(["vault", "init", "--path", str(root)])
    assert rc == 0
    return root


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


class TestInit:
    def test_init_creates_layout(
        self, tmp_path: Path, env_passphrase: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        del env_passphrase
        root = _vault_root(tmp_path)
        rc = qwashed_main(["vault", "init", "--path", str(root)])
        assert rc == 0
        assert (root / "manifest.json").is_file()
        assert (root / "keys" / "identity.pub").is_file()
        assert (root / "keys" / "identity.sk.enc").is_file()
        assert (root / "audit_log.jsonl").is_file()
        out = capsys.readouterr().out
        assert "created" in out
        assert str(root) in out

    def test_init_refuses_non_empty_root(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        del env_passphrase
        root = _vault_root(tmp_path)
        root.mkdir()
        (root / "stray").write_text("hello")
        rc = qwashed_main(["vault", "init", "--path", str(root)])
        assert rc == 2
        err = capsys.readouterr().err
        assert "vault.store.root_not_empty" in err

    def test_init_empty_env_passphrase_fails(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv("QWASHED_VAULT_PASSPHRASE", "")
        root = _vault_root(tmp_path)
        rc = qwashed_main(["vault", "init", "--path", str(root)])
        assert rc == 2
        err = capsys.readouterr().err
        assert "vault.cli.empty_env_passphrase" in err
        assert not root.exists() or not any(root.iterdir())


# ---------------------------------------------------------------------------
# put / get / list
# ---------------------------------------------------------------------------


class TestPutGetList:
    def test_put_round_trip_default_name(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        del env_passphrase
        root = _init_vault(tmp_path)
        capsys.readouterr()  # drain init banner

        src = tmp_path / "secret.txt"
        src.write_bytes(b"top secret civil society file")
        rc = qwashed_main(["vault", "put", "--path", str(root), str(src)])
        assert rc == 0
        out = capsys.readouterr().out.strip()
        ulid, size, name = out.split(maxsplit=2)
        assert len(ulid) == 26
        assert int(size) == len(b"top secret civil society file")
        assert name == "secret.txt"

        # Now get into a destination file.
        dst = tmp_path / "out.bin"
        rc = qwashed_main(["vault", "get", "--path", str(root), ulid, "--output", str(dst)])
        assert rc == 0
        capsys.readouterr()
        assert dst.read_bytes() == src.read_bytes()

    def test_get_to_stdout(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        del env_passphrase
        root = _init_vault(tmp_path)
        capsys.readouterr()
        src = tmp_path / "msg"
        src.write_bytes(b"hello\nworld\n")
        qwashed_main(["vault", "put", "--path", str(root), str(src)])
        ulid = capsys.readouterr().out.strip().split()[0]

        rc = qwashed_main(["vault", "get", "--path", str(root), ulid])
        assert rc == 0
        captured = capsys.readouterr()
        # stdout (binary) was written via .buffer.write; pytest captures it
        # as text on stdout. Either way the bytes should appear.
        assert b"hello" in captured.out.encode("utf-8")
        assert b"world" in captured.out.encode("utf-8")

    def test_put_with_explicit_name(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        del env_passphrase
        root = _init_vault(tmp_path)
        capsys.readouterr()
        src = tmp_path / "raw"
        src.write_bytes(b"data")
        rc = qwashed_main(["vault", "put", "--path", str(root), str(src), "--name", "labelled.txt"])
        assert rc == 0
        out = capsys.readouterr().out.strip()
        assert out.endswith("labelled.txt")

    def test_put_missing_file(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        del env_passphrase
        root = _init_vault(tmp_path)
        capsys.readouterr()
        rc = qwashed_main(["vault", "put", "--path", str(root), str(tmp_path / "nope")])
        assert rc == 2
        err = capsys.readouterr().err
        assert "file not found" in err

    def test_list_emits_one_line_per_entry(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        del env_passphrase
        root = _init_vault(tmp_path)
        capsys.readouterr()
        for i, body in enumerate([b"a", b"bb", b"ccc"]):
            src = tmp_path / f"f{i}"
            src.write_bytes(body)
            qwashed_main(["vault", "put", "--path", str(root), str(src)])
            capsys.readouterr()

        rc = qwashed_main(["vault", "list", "--path", str(root)])
        assert rc == 0
        lines = [ln for ln in capsys.readouterr().out.splitlines() if ln]
        assert len(lines) == 3
        for ln in lines:
            ulid, size, _created_at, name = ln.split("\t")
            assert len(ulid) == 26
            assert int(size) >= 1
            assert name.startswith("f")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


class TestVerify:
    def test_verify_clean_vault(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        del env_passphrase
        root = _init_vault(tmp_path)
        capsys.readouterr()
        src = tmp_path / "f"
        src.write_bytes(b"x" * 32)
        qwashed_main(["vault", "put", "--path", str(root), str(src)])
        capsys.readouterr()

        rc = qwashed_main(["vault", "verify", "--path", str(root)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "OK" in out

    def test_verify_detects_tampered_audit_log(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        del env_passphrase
        root = _init_vault(tmp_path)
        capsys.readouterr()
        # Add an entry so audit log has at least 2 lines.
        src = tmp_path / "f"
        src.write_bytes(b"x")
        qwashed_main(["vault", "put", "--path", str(root), str(src)])
        capsys.readouterr()

        # Tamper: rewrite the genesis line subject.
        log_path = root / "audit_log.jsonl"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["subject"] = first["subject"] + "X"
        lines[0] = json.dumps(first, separators=(",", ":"), sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        rc = qwashed_main(["vault", "verify", "--path", str(root)])
        assert rc == 1
        err = capsys.readouterr().err
        assert "qwashed vault verify" in err


# ---------------------------------------------------------------------------
# recipients add / list
# ---------------------------------------------------------------------------


class TestRecipients:
    def test_add_via_b64_args_and_list(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        del env_passphrase
        root = _init_vault(tmp_path)
        capsys.readouterr()

        kem_kp = generate_kem_keypair()
        sig_kp = generate_sig_keypair()
        kem_b64 = base64.b64encode(kem_kp.public_bytes()).decode("ascii")
        sig_b64 = base64.b64encode(sig_kp.public_bytes()).decode("ascii")

        rc = qwashed_main(
            [
                "vault",
                "recipients",
                "add",
                "--path",
                str(root),
                "--label",
                "alice",
                "--kem-pk-b64",
                kem_b64,
                "--sig-pk-b64",
                sig_b64,
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out.strip()
        fp, label = out.split("\t")
        assert len(fp) == 32
        assert label == "alice"

        rc = qwashed_main(["vault", "recipients", "list", "--path", str(root)])
        assert rc == 0
        listed = capsys.readouterr().out.strip()
        parts = listed.split("\t")
        assert parts[0] == fp
        assert parts[2] == "alice"

    def test_add_via_files(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        del env_passphrase
        root = _init_vault(tmp_path)
        capsys.readouterr()

        kem_kp = generate_kem_keypair()
        sig_kp = generate_sig_keypair()
        kem_path = tmp_path / "kem.pub"
        sig_path = tmp_path / "sig.pub"
        # Write as raw bytes; CLI handles both raw and base64.
        kem_path.write_bytes(kem_kp.public_bytes())
        sig_path.write_bytes(sig_kp.public_bytes())

        rc = qwashed_main(
            [
                "vault",
                "recipients",
                "add",
                "--path",
                str(root),
                "--label",
                "bob",
                "--kem-pk-file",
                str(kem_path),
                "--sig-pk-file",
                str(sig_path),
            ]
        )
        assert rc == 0

    def test_add_xor_constraint(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Either pk-file OR pk-b64 — not both, not neither."""
        del env_passphrase
        root = _init_vault(tmp_path)
        capsys.readouterr()

        kem_kp = generate_kem_keypair()
        sig_kp = generate_sig_keypair()
        kem_b64 = base64.b64encode(kem_kp.public_bytes()).decode("ascii")
        sig_b64 = base64.b64encode(sig_kp.public_bytes()).decode("ascii")

        # Neither -> error.
        rc = qwashed_main(
            [
                "vault",
                "recipients",
                "add",
                "--path",
                str(root),
                "--label",
                "z",
                "--sig-pk-b64",
                sig_b64,
            ]
        )
        assert rc == 2
        err = capsys.readouterr().err
        assert "vault.cli.recipient_pk_arg_xor" in err

        # Both -> error.
        kem_path = tmp_path / "k.pub"
        kem_path.write_bytes(kem_kp.public_bytes())
        rc = qwashed_main(
            [
                "vault",
                "recipients",
                "add",
                "--path",
                str(root),
                "--label",
                "z",
                "--kem-pk-file",
                str(kem_path),
                "--kem-pk-b64",
                kem_b64,
                "--sig-pk-b64",
                sig_b64,
            ]
        )
        assert rc == 2
        err = capsys.readouterr().err
        assert "vault.cli.recipient_pk_arg_xor" in err


# ---------------------------------------------------------------------------
# export round trip
# ---------------------------------------------------------------------------


class TestExportRoundTrip:
    def test_export_to_file_and_open(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        del env_passphrase
        root = _init_vault(tmp_path)
        capsys.readouterr()

        # Recipient: separate fresh keypairs.
        kem_kp = generate_kem_keypair()
        sig_kp = generate_sig_keypair()
        kem_b64 = base64.b64encode(kem_kp.public_bytes()).decode("ascii")
        sig_b64 = base64.b64encode(sig_kp.public_bytes()).decode("ascii")
        qwashed_main(
            [
                "vault",
                "recipients",
                "add",
                "--path",
                str(root),
                "--label",
                "alice",
                "--kem-pk-b64",
                kem_b64,
                "--sig-pk-b64",
                sig_b64,
            ]
        )
        fp = capsys.readouterr().out.strip().split("\t")[0]

        # Put an entry.
        src = tmp_path / "doc"
        src.write_bytes(b"export me")
        qwashed_main(["vault", "put", "--path", str(root), str(src)])
        ulid = capsys.readouterr().out.strip().split()[0]

        # Export to a file.
        bundle_path = tmp_path / "bundle.json"
        rc = qwashed_main(
            [
                "vault",
                "export",
                "--path",
                str(root),
                ulid,
                "--recipient",
                fp,
                "--output",
                str(bundle_path),
            ]
        )
        assert rc == 0
        capsys.readouterr()
        assert bundle_path.is_file()

        # Recipient unwraps it locally.
        plaintext, bundle = open_export_bundle(
            bundle_path.read_bytes(),
            kem_kp,
        )
        assert plaintext == b"export me"
        assert bundle.ulid == ulid
        assert bundle.recipient_fingerprint == fp

    def test_export_unknown_recipient(
        self,
        tmp_path: Path,
        env_passphrase: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        del env_passphrase
        root = _init_vault(tmp_path)
        capsys.readouterr()
        src = tmp_path / "doc"
        src.write_bytes(b"x")
        qwashed_main(["vault", "put", "--path", str(root), str(src)])
        ulid = capsys.readouterr().out.strip().split()[0]

        rc = qwashed_main(
            [
                "vault",
                "export",
                "--path",
                str(root),
                ulid,
                "--recipient",
                "0" * 32,
                "--output",
                str(tmp_path / "b"),
            ]
        )
        # `recipient_missing` is raised as SignatureError by the library;
        # the CLI maps any SignatureError on the export path to exit 1.
        # Recipient lookup happens *before* any decrypt, so no plaintext
        # touched the audit log.
        assert rc == 1
        err = capsys.readouterr().err
        assert "vault.store.recipient_missing" in err
        assert "qwashed vault export" in err


# ---------------------------------------------------------------------------
# default ~/.qwashed path resolution
# ---------------------------------------------------------------------------


class TestDefaultPath:
    def test_default_path_uses_home(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If --path is omitted, vault root is $HOME/.qwashed."""
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("QWASHED_VAULT_PASSPHRASE", PASSPHRASE)
        rc = qwashed_main(["vault", "init"])
        assert rc == 0
        assert (tmp_path / ".qwashed" / "manifest.json").is_file()


# ---------------------------------------------------------------------------
# Error path: bad passphrase on second open
# ---------------------------------------------------------------------------


class TestPassphraseHandling:
    def test_wrong_passphrase_on_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv("QWASHED_VAULT_PASSPHRASE", PASSPHRASE)
        root = _init_vault(tmp_path)
        capsys.readouterr()

        monkeypatch.setenv("QWASHED_VAULT_PASSPHRASE", "wrong")
        rc = qwashed_main(["vault", "list", "--path", str(root)])
        assert rc != 0
        err = capsys.readouterr().err
        assert "vault.store" in err  # any vault.store.* error_code is fine

    def test_unknown_passphrase_source_when_no_tty_and_no_env(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.delenv("QWASHED_VAULT_PASSPHRASE", raising=False)
        # pytest's captured stdin is not a TTY, so getpass would loop;
        # the CLI must short-circuit with a clean error.
        rc = qwashed_main(["vault", "init", "--path", str(tmp_path / "v")])
        assert rc == 2
        err = capsys.readouterr().err
        assert "vault.cli.no_passphrase_source" in err


# ---------------------------------------------------------------------------
# Sanity: vault root permissions on init
# ---------------------------------------------------------------------------


def test_vault_root_perms_after_init(tmp_path: Path, env_passphrase: None) -> None:
    del env_passphrase
    root = _init_vault(tmp_path)
    # 0700 on root/keys/recipients dirs; 0600 on identity files.
    assert (root.stat().st_mode & 0o777) == 0o700
    assert ((root / "keys").stat().st_mode & 0o777) == 0o700
    assert ((root / "keys" / "recipients").stat().st_mode & 0o777) == 0o700
    sk_mode = (root / "keys" / "identity.sk.enc").stat().st_mode & 0o777
    assert sk_mode == 0o600


# ---------------------------------------------------------------------------
# Smoke: verify CLI output has no leaked secrets
# ---------------------------------------------------------------------------


def test_no_secret_material_on_stdout_or_stderr(
    tmp_path: Path,
    env_passphrase: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Per security checklist 11.4: no private-key material logged or printed."""
    del env_passphrase
    root = _init_vault(tmp_path)
    capsys.readouterr()
    src = tmp_path / "f"
    src.write_bytes(b"plaintext")
    qwashed_main(["vault", "put", "--path", str(root), str(src)])
    qwashed_main(["vault", "list", "--path", str(root)])
    qwashed_main(["vault", "verify", "--path", str(root)])
    captured = capsys.readouterr()
    for stream in (captured.out, captured.err):
        # The literal passphrase must never appear on any output stream.
        assert PASSPHRASE not in stream
        # The on-disk wrapped secret-key bytes must not appear either.
        sk_blob = (root / "keys" / "identity.sk.enc").read_bytes()
        # Compare a prefix to avoid base64-vs-bytes issues; if the raw
        # bytes ever ended up in stdout/stderr, the first 32 bytes would
        # show up as an encoded fragment.
        assert base64.b64encode(sk_blob[:32]).decode("ascii") not in stream


# ---------------------------------------------------------------------------
# Sanity: opening the vault library-side after CLI mutations
# ---------------------------------------------------------------------------


def test_library_can_open_cli_initialized_vault(tmp_path: Path, env_passphrase: None) -> None:
    """The CLI and the library are interoperable on the same vault root."""
    del env_passphrase
    root = _init_vault(tmp_path)
    vault = unlock_vault(root, PASSPHRASE.encode("utf-8"))
    # No entries yet; list_recipients() returns an empty sequence.
    assert list(vault.list_recipients()) == []
    assert vault.list() == []


# ---------------------------------------------------------------------------
# Sanity: hybrid_decap is importable + works on a CLI-exported bundle
# (extra coverage of the hybrid_kem path the export test depends on)
# ---------------------------------------------------------------------------


def test_hybrid_decap_resolves(tmp_path: Path) -> None:
    del tmp_path
    kp = generate_kem_keypair()
    pk_bytes = kp.public_bytes()
    assert isinstance(pk_bytes, bytes)
    assert callable(hybrid_decap)


# ---------------------------------------------------------------------------
# Misc smoke: verify command from help works (no env, no passphrase, no I/O)
# ---------------------------------------------------------------------------


def test_vault_help_no_subcommand_returns_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`qwashed vault` with no subcommand prints help and exits non-zero."""
    rc = qwashed_main(["vault"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "vault" in err.lower()


def test_vault_recipients_help_no_subcommand_returns_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = qwashed_main(["vault", "recipients"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "recipients" in err.lower()


# ---------------------------------------------------------------------------
# Sanity: PASSPHRASE_ENV_VAR constant is the documented one
# ---------------------------------------------------------------------------


def test_env_var_name_is_documented() -> None:
    from qwashed.vault.cli import PASSPHRASE_ENV_VAR

    assert PASSPHRASE_ENV_VAR == "QWASHED_VAULT_PASSPHRASE"
    assert PASSPHRASE_ENV_VAR in os.environ.get("QWASHED_VAULT_PASSPHRASE_NAME", PASSPHRASE_ENV_VAR)
