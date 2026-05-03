# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.vault.store.

Covers:

* :func:`init_vault` lays down the expected directory layout, files have
  ``0o600`` permissions, dirs have ``0o700`` permissions, the manifest is
  hybrid-signed, and the audit log's genesis line is op=``init``.
* :func:`unlock_vault` reproduces the same identity from disk and rejects
  wrong passphrases / tampered envelopes / missing files.
* :meth:`Vault.put` / :meth:`Vault.get` round-trip plaintext byte-for-byte
  and produce a verifiable audit-log line per operation.
* :meth:`Vault.list` returns parsed metadata for every entry, sorted.
* :meth:`Vault.verify` accepts a clean vault and rejects every tamper:
  flipped meta byte, swapped blob, deleted audit-log line.
* The :data:`BLOB_MAGIC` / :data:`BLOB_VERSION` header is what the writer
  actually emits.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings(
    "ignore",
    message=r"liboqs version .* differs",
    category=UserWarning,
)

from qwashed.core.canonical import canonicalize  # noqa: E402
from qwashed.core.errors import (  # noqa: E402
    ConfigurationError,
    SchemaValidationError,
    SignatureError,
)
from qwashed.core.kdf import ARGON2ID_MIN_MEMORY_KIB, ARGON2ID_MIN_TIME_COST  # noqa: E402
from qwashed.vault.audit_log import verify_chain  # noqa: E402
from qwashed.vault.store import (  # noqa: E402
    BLOB_MAGIC,
    BLOB_VERSION,
    DIR_MODE,
    FILE_MODE,
    Vault,
    init_vault,
    new_ulid,
    unlock_vault,
)

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

_PASSPHRASE = b"correct-horse-battery-staple"
_WRONG_PASSPHRASE = b"wrong-horse-empty-staple"

# Use the OWASP minimum Argon2id parameters in tests to keep init/unlock
# fast (~50ms each) without dropping below the fail-closed minimum.
_FAST_ARGON = {
    "memory_kib": ARGON2ID_MIN_MEMORY_KIB,
    "time_cost": ARGON2ID_MIN_TIME_COST,
    "parallelism": 1,
}


@pytest.fixture
def fresh_vault(tmp_path: Path) -> Vault:
    return init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)


# ---------------------------------------------------------------------------
# ULID
# ---------------------------------------------------------------------------


class TestUlid:
    def test_length_and_alphabet(self) -> None:
        u = new_ulid()
        assert len(u) == 26
        assert all(c in "0123456789ABCDEFGHJKMNPQRSTVWXYZ" for c in u)

    def test_uniqueness(self) -> None:
        seen = {new_ulid() for _ in range(100)}
        assert len(seen) == 100


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------


class TestInit:
    def test_layout_and_files_exist(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        v = init_vault(root, _PASSPHRASE, **_FAST_ARGON)
        assert v.root == root
        assert (root / "manifest.json").is_file()
        assert (root / "keys" / "identity.pub").is_file()
        assert (root / "keys" / "identity.sk.enc").is_file()
        assert (root / "keys" / "recipients").is_dir()
        assert (root / "entries").is_dir()
        assert (root / "audit_log.jsonl").is_file()

    def test_file_permissions(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        init_vault(root, _PASSPHRASE, **_FAST_ARGON)
        for fp in (
            root / "manifest.json",
            root / "keys" / "identity.pub",
            root / "keys" / "identity.sk.enc",
        ):
            mode = stat.S_IMODE(fp.stat().st_mode)
            assert mode == FILE_MODE, f"{fp} is {oct(mode)}, expected {oct(FILE_MODE)}"

    def test_directory_permissions(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        init_vault(root, _PASSPHRASE, **_FAST_ARGON)
        for dp in (
            root,
            root / "keys",
            root / "keys" / "recipients",
            root / "entries",
        ):
            mode = stat.S_IMODE(dp.stat().st_mode)
            assert mode == DIR_MODE, f"{dp} is {oct(mode)}, expected {oct(DIR_MODE)}"

    def test_manifest_signed(self, tmp_path: Path) -> None:
        v = init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)
        assert v.manifest.sig_hybrid_b64
        # Round-trip canonical body must match what's on disk.
        on_disk = json.loads((v.root / "manifest.json").read_text())
        assert on_disk["sig_hybrid"] == v.manifest.sig_hybrid_b64

    def test_genesis_audit_line(self, tmp_path: Path) -> None:
        v = init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)
        entries = verify_chain(v.root / "audit_log.jsonl")
        assert len(entries) == 1
        assert entries[0].op == "init"
        assert entries[0].subject.startswith("vault://")

    def test_init_refuses_non_empty_root(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        root.mkdir()
        (root / "occupied").write_text("existing")
        with pytest.raises(ConfigurationError):
            init_vault(root, _PASSPHRASE, **_FAST_ARGON)

    def test_init_rejects_empty_passphrase(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            init_vault(tmp_path / "v", b"", **_FAST_ARGON)

    def test_init_rejects_non_bytes_passphrase(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            init_vault(tmp_path / "v", "string", **_FAST_ARGON)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Unlock
# ---------------------------------------------------------------------------


class TestUnlock:
    def test_unlock_round_trip(self, tmp_path: Path) -> None:
        v1 = init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)
        v2 = unlock_vault(v1.root, _PASSPHRASE)
        # Same identity on both sides.
        assert v1.identity.kem.public_bytes() == v2.identity.kem.public_bytes()
        assert v1.identity.sig.public_bytes() == v2.identity.sig.public_bytes()
        assert v1.identity.kem.x25519_sk == v2.identity.kem.x25519_sk
        assert v1.identity.sig.mldsa65_sk == v2.identity.sig.mldsa65_sk

    def test_unlock_wrong_passphrase(self, tmp_path: Path) -> None:
        v = init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)
        with pytest.raises(SignatureError):
            unlock_vault(v.root, _WRONG_PASSPHRASE)

    def test_unlock_empty_passphrase(self, tmp_path: Path) -> None:
        v = init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)
        with pytest.raises(ConfigurationError):
            unlock_vault(v.root, b"")

    def test_unlock_missing_root(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            unlock_vault(tmp_path / "nope", _PASSPHRASE)

    def test_unlock_missing_required_file(self, tmp_path: Path) -> None:
        v = init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)
        (v.root / "keys" / "identity.sk.enc").unlink()
        with pytest.raises(ConfigurationError):
            unlock_vault(v.root, _PASSPHRASE)

    def test_unlock_tampered_manifest(self, tmp_path: Path) -> None:
        v = init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)
        manifest_path = v.root / "manifest.json"
        doc = json.loads(manifest_path.read_text())
        doc["vault_id"] = new_ulid()  # different id; signature will not verify
        manifest_path.write_bytes(canonicalize(doc))
        with pytest.raises(SignatureError):
            unlock_vault(v.root, _PASSPHRASE)


# ---------------------------------------------------------------------------
# Put / Get round trip
# ---------------------------------------------------------------------------


class TestPutGet:
    def test_round_trip(self, fresh_vault: Vault) -> None:
        plaintext = b"hello qwashed vault"
        meta = fresh_vault.put(plaintext, name="greeting.txt")
        assert meta.size == len(plaintext)
        assert len(meta.ulid) == 26
        assert (fresh_vault.root / "entries" / f"{meta.ulid}.bin").is_file()
        assert (fresh_vault.root / "entries" / f"{meta.ulid}.meta.json").is_file()

        got, got_meta = fresh_vault.get(meta.ulid)
        assert got == plaintext
        assert got_meta.ulid == meta.ulid
        assert got_meta.name == "greeting.txt"

    def test_round_trip_empty_payload(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"", name="empty")
        plaintext, _ = fresh_vault.get(meta.ulid)
        assert plaintext == b""

    def test_round_trip_after_unlock(self, tmp_path: Path) -> None:
        v1 = init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)
        meta = v1.put(b"persisted", name="x")
        v2 = unlock_vault(v1.root, _PASSPHRASE)
        plaintext, _ = v2.get(meta.ulid)
        assert plaintext == b"persisted"

    def test_blob_header_format(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"x", name="x")
        blob = (fresh_vault.root / "entries" / f"{meta.ulid}.bin").read_bytes()
        assert blob[0:4] == BLOB_MAGIC
        assert blob[4] == BLOB_VERSION
        assert blob[5:8] == b"\x00\x00\x00"

    def test_put_empty_name_rejected(self, fresh_vault: Vault) -> None:
        with pytest.raises(SchemaValidationError):
            fresh_vault.put(b"x", name="")

    def test_get_unknown_ulid(self, fresh_vault: Vault) -> None:
        with pytest.raises(SignatureError):
            fresh_vault.get(new_ulid())

    def test_get_malformed_ulid(self, fresh_vault: Vault) -> None:
        with pytest.raises(SchemaValidationError):
            fresh_vault.get("too-short")

    def test_get_lowercase_ulid_rejected(self, fresh_vault: Vault) -> None:
        # Crockford base32 is uppercase only; lowercase is malformed.
        u = new_ulid().lower()
        with pytest.raises(SchemaValidationError):
            fresh_vault.get(u)

    def test_put_creates_audit_line(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"x", name="x")
        entries = verify_chain(fresh_vault.root / "audit_log.jsonl")
        ops = [e.op for e in entries]
        assert ops == ["init", "put"]
        assert entries[1].subject == meta.ulid

    def test_get_creates_audit_line(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"x", name="x")
        fresh_vault.get(meta.ulid)
        entries = verify_chain(fresh_vault.root / "audit_log.jsonl")
        ops = [e.op for e in entries]
        assert ops == ["init", "put", "get"]


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


class TestList:
    def test_empty_vault(self, fresh_vault: Vault) -> None:
        assert fresh_vault.list() == []

    def test_multiple_entries_sorted(self, fresh_vault: Vault) -> None:
        ulids = []
        for i in range(3):
            meta = fresh_vault.put(f"payload-{i}".encode(), name=f"e-{i}")
            ulids.append(meta.ulid)
        listed = fresh_vault.list()
        assert [m.ulid for m in listed] == sorted(ulids)

    def test_list_rejects_tampered_meta(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"x", name="x")
        meta_path = fresh_vault.root / "entries" / f"{meta.ulid}.meta.json"
        doc = json.loads(meta_path.read_text())
        doc["name"] = "TAMPERED"
        meta_path.write_bytes(canonicalize(doc))
        with pytest.raises(SignatureError):
            fresh_vault.list()


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


class TestVerify:
    def test_clean_vault_verifies(self, fresh_vault: Vault) -> None:
        for i in range(2):
            fresh_vault.put(f"p-{i}".encode(), name=f"e-{i}")
        fresh_vault.verify()  # no exception

    def test_tampered_meta_fails(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"data", name="x")
        meta_path = fresh_vault.root / "entries" / f"{meta.ulid}.meta.json"
        doc = json.loads(meta_path.read_text())
        doc["size"] = 9999
        meta_path.write_bytes(canonicalize(doc))
        with pytest.raises(SignatureError):
            fresh_vault.verify()

    def test_tampered_blob_fails(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"data", name="x")
        blob_path = fresh_vault.root / "entries" / f"{meta.ulid}.bin"
        blob = bytearray(blob_path.read_bytes())
        # Flip a byte deep inside the AEAD ciphertext (well past header
        # + KEM ciphertext + nonce). This invalidates the SHA-256 hash
        # in the metadata.
        blob[-3] ^= 0x01
        blob_path.write_bytes(bytes(blob))
        with pytest.raises(SignatureError):
            fresh_vault.verify()

    def test_missing_blob_fails(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"data", name="x")
        (fresh_vault.root / "entries" / f"{meta.ulid}.bin").unlink()
        with pytest.raises(SignatureError):
            fresh_vault.verify()

    def test_audit_log_truncation_loses_entry(self, fresh_vault: Vault) -> None:
        # Put one entry, then delete the audit log's "put" line by
        # rewriting the log to only contain the genesis line.
        fresh_vault.put(b"data", name="x")
        log_path = fresh_vault.root / "audit_log.jsonl"
        lines = log_path.read_bytes().split(b"\n")
        # lines[0] == genesis, lines[1] == put, lines[2] == "" trailing
        log_path.write_bytes(lines[0] + b"\n")
        with pytest.raises(SignatureError):
            fresh_vault.verify()


# ---------------------------------------------------------------------------
# Tampered AEAD on get
# ---------------------------------------------------------------------------


class TestTamperedGet:
    def test_get_after_blob_tamper_fails(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"data", name="x")
        blob_path = fresh_vault.root / "entries" / f"{meta.ulid}.bin"
        blob = bytearray(blob_path.read_bytes())
        blob[-1] ^= 0x01
        blob_path.write_bytes(bytes(blob))
        with pytest.raises(SignatureError):
            fresh_vault.get(meta.ulid)

    def test_get_after_meta_tamper_fails(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"data", name="x")
        meta_path = fresh_vault.root / "entries" / f"{meta.ulid}.meta.json"
        doc = json.loads(meta_path.read_text())
        doc["size"] = 0
        meta_path.write_bytes(canonicalize(doc))
        with pytest.raises(SignatureError):
            fresh_vault.get(meta.ulid)

    def test_swap_blob_between_entries_detected(self, fresh_vault: Vault) -> None:
        m1 = fresh_vault.put(b"alpha", name="a")
        m2 = fresh_vault.put(b"beta12", name="b")
        # Swap raw blob bytes between the two entries.
        b1 = fresh_vault.root / "entries" / f"{m1.ulid}.bin"
        b2 = fresh_vault.root / "entries" / f"{m2.ulid}.bin"
        data1, data2 = b1.read_bytes(), b2.read_bytes()
        b1.write_bytes(data2)
        b2.write_bytes(data1)
        # Each get must fail: blob_sha256 in meta no longer matches, or
        # AEAD AAD (which is the entry's own ULID) no longer matches.
        with pytest.raises(SignatureError):
            fresh_vault.get(m1.ulid)
        with pytest.raises(SignatureError):
            fresh_vault.get(m2.ulid)


# ---------------------------------------------------------------------------
# Identity envelope tampering
# ---------------------------------------------------------------------------


class TestIdentityEnvelope:
    def test_tampered_ciphertext_fails(self, tmp_path: Path) -> None:
        v = init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)
        sk_enc_path = v.root / "keys" / "identity.sk.enc"
        env = json.loads(sk_enc_path.read_text())
        ct = bytearray(base64.b64decode(env["ciphertext_b64"]))
        ct[5] ^= 0x01
        env["ciphertext_b64"] = base64.b64encode(bytes(ct)).decode("ascii")
        sk_enc_path.write_bytes(canonicalize(env))
        with pytest.raises(SignatureError):
            unlock_vault(v.root, _PASSPHRASE)

    def test_truncated_envelope_fails(self, tmp_path: Path) -> None:
        v = init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)
        sk_enc_path = v.root / "keys" / "identity.sk.enc"
        sk_enc_path.write_bytes(b'{"version": 1}')
        with pytest.raises(SchemaValidationError):
            unlock_vault(v.root, _PASSPHRASE)


# ---------------------------------------------------------------------------
# Concurrent writers / chain head
# ---------------------------------------------------------------------------


class TestChainAcrossOps:
    def test_chain_consistent_after_many_ops(self, fresh_vault: Vault) -> None:
        ulids = []
        for i in range(4):
            ulids.append(fresh_vault.put(f"p{i}".encode(), name=f"e{i}").ulid)
        for u in ulids:
            fresh_vault.get(u)
        entries = verify_chain(fresh_vault.root / "audit_log.jsonl")
        ops = [e.op for e in entries]
        assert ops == ["init", "put", "put", "put", "put", "get", "get", "get", "get"]


# ---------------------------------------------------------------------------
# Audit-log permission tightening
# ---------------------------------------------------------------------------


class TestAuditLogPermissions:
    def test_audit_log_perm_after_init(self, tmp_path: Path) -> None:
        v = init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)
        log_path = v.root / "audit_log.jsonl"
        mode = stat.S_IMODE(log_path.stat().st_mode)
        # On platforms where chmod isn't supported (rare), accept >=
        # owner-rw at minimum, but on POSIX we expect 0o600.
        if os.name == "posix":
            assert mode == FILE_MODE


# ---------------------------------------------------------------------------
# Export operation
# ---------------------------------------------------------------------------


from qwashed.vault.hybrid_kem import (  # noqa: E402
    generate_keypair as generate_kem_keypair,
)
from qwashed.vault.hybrid_sig import (  # noqa: E402
    generate_keypair as generate_sig_keypair,
)
from qwashed.vault.store import (  # noqa: E402
    EXPORT_SIG_DOMAIN,
    EXPORT_VERSION,
    RECIPIENT_VERSION,
    ExportBundle,
    Recipient,
    open_export_bundle,
)


def _make_recipient_keys() -> tuple[bytes, bytes, object, object]:
    """Build a fresh hybrid KEM + SIG keypair for an external recipient.

    Returns ``(serialized_kem_pub, serialized_sig_pub, kem_keypair, sig_keypair)``.
    Test code only needs the kem_keypair to call open_export_bundle.
    """
    kem = generate_kem_keypair()
    sig = generate_sig_keypair()
    return kem.public_bytes(), sig.public_bytes(), kem, sig


class TestRecipientAdd:
    def test_add_recipient_writes_pub_file(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        path = fresh_vault.root / "keys" / "recipients" / f"{r.fingerprint}.pub"
        assert path.is_file()
        assert r.label == "alice"
        assert r.version == RECIPIENT_VERSION
        assert len(r.fingerprint) == 32
        # Fingerprint must be lowercase hex.
        assert all(c in "0123456789abcdef" for c in r.fingerprint)

    def test_add_recipient_file_mode(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        path = fresh_vault.root / "keys" / "recipients" / f"{r.fingerprint}.pub"
        if os.name == "posix":
            mode = stat.S_IMODE(path.stat().st_mode)
            assert mode == FILE_MODE

    def test_add_recipient_dir_mode(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        recip_dir = fresh_vault.root / "keys" / "recipients"
        if os.name == "posix":
            mode = stat.S_IMODE(recip_dir.stat().st_mode)
            assert mode == DIR_MODE

    def test_add_recipient_empty_label_rejected(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        with pytest.raises(SchemaValidationError):
            fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="")

    def test_add_recipient_empty_pk_rejected(self, fresh_vault: Vault) -> None:
        with pytest.raises(SchemaValidationError):
            fresh_vault.add_recipient(kem_pk=b"", sig_pk=b"x", label="alice")
        with pytest.raises(SchemaValidationError):
            fresh_vault.add_recipient(kem_pk=b"x", sig_pk=b"", label="alice")

    def test_add_recipient_non_bytes_pk_rejected(self, fresh_vault: Vault) -> None:
        with pytest.raises(SchemaValidationError):
            fresh_vault.add_recipient(
                kem_pk="not-bytes",  # type: ignore[arg-type]
                sig_pk=b"x",
                label="alice",
            )

    def test_add_recipient_duplicate_rejected(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        with pytest.raises(ConfigurationError):
            fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice2")

    def test_fingerprint_is_deterministic(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r1 = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        # Adding a *different* recipient must produce a different fp.
        kem2, sig2, _, _ = _make_recipient_keys()
        r2 = fresh_vault.add_recipient(kem_pk=kem2, sig_pk=sig2, label="bob")
        assert r1.fingerprint != r2.fingerprint


class TestRecipientList:
    def test_empty(self, fresh_vault: Vault) -> None:
        assert list(fresh_vault.list_recipients()) == []

    def test_multiple_sorted(self, fresh_vault: Vault) -> None:
        added = []
        for label in ["a", "b", "c"]:
            kem_pub, sig_pub, _, _ = _make_recipient_keys()
            r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label=label)
            added.append(r.fingerprint)
        listed = [r.fingerprint for r in fresh_vault.list_recipients()]
        assert listed == sorted(added)

    def test_tampered_recipient_file_rejected(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        path = fresh_vault.root / "keys" / "recipients" / f"{r.fingerprint}.pub"
        # Flip the label; fingerprint in body still matches filename, but
        # body fingerprint won't match the *derived* hash of the (modified)
        # pubkeys. Wait - changing label doesn't affect derived fingerprint
        # because derived = sha256(kem || sig). So this won't be caught
        # unless the label-tamper also changes pubkey bytes.
        # Instead: corrupt the kem_pk so fingerprint check fails.
        doc = json.loads(path.read_text())
        # Corrupt kem_pk by flipping a base64 char.
        original = doc["kem_pk"]
        doc["kem_pk"] = "A" + original[1:] if original[0] != "A" else "B" + original[1:]
        path.write_bytes(canonicalize(doc))
        with pytest.raises(SignatureError):
            list(fresh_vault.list_recipients())

    def test_tampered_fingerprint_filename_rejected(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        recip_dir = fresh_vault.root / "keys" / "recipients"
        # Rename to a wrong fingerprint.
        old = recip_dir / f"{r.fingerprint}.pub"
        wrong_fp = "0" * 32
        new = recip_dir / f"{wrong_fp}.pub"
        old.rename(new)
        with pytest.raises(SignatureError):
            list(fresh_vault.list_recipients())


class TestRecipientGet:
    def test_get_existing(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        got = fresh_vault.get_recipient(r.fingerprint)
        assert got.fingerprint == r.fingerprint
        assert got.label == "alice"

    def test_get_missing(self, fresh_vault: Vault) -> None:
        with pytest.raises(SignatureError):
            fresh_vault.get_recipient("0" * 32)

    def test_get_bad_fingerprint(self, fresh_vault: Vault) -> None:
        with pytest.raises(SchemaValidationError):
            fresh_vault.get_recipient("xyz")  # too short
        with pytest.raises(SchemaValidationError):
            fresh_vault.get_recipient("Z" * 32)  # non-hex
        with pytest.raises(SchemaValidationError):
            fresh_vault.get_recipient("AB" * 16)  # uppercase hex


class TestExportRoundTrip:
    def test_export_roundtrip(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"top-secret-document", name="dossier.txt")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        plaintext, bundle = open_export_bundle(bundle_bytes, recipient_kem)  # type: ignore[arg-type]
        assert plaintext == b"top-secret-document"
        assert bundle.ulid == meta.ulid
        assert bundle.name == "dossier.txt"
        assert bundle.size == len(b"top-secret-document")
        assert bundle.recipient_fingerprint == r.fingerprint
        assert bundle.version == EXPORT_VERSION

    def test_export_empty_payload(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"", name="empty.bin")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        plaintext, bundle = open_export_bundle(bundle_bytes, recipient_kem)  # type: ignore[arg-type]
        assert plaintext == b""
        assert bundle.size == 0

    def test_export_writes_audit_line(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="x")
        fresh_vault.export(meta.ulid, r.fingerprint)
        entries = verify_chain(fresh_vault.root / "audit_log.jsonl")
        ops = [e.op for e in entries]
        assert ops == ["init", "put", "export"]
        assert entries[-1].subject == f"{meta.ulid}|to={r.fingerprint}"

    def test_export_to_unknown_recipient_fails(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"hello", name="x")
        with pytest.raises(SignatureError):
            fresh_vault.export(meta.ulid, "0" * 32)
        # Audit log must NOT contain a spurious export line.
        entries = verify_chain(fresh_vault.root / "audit_log.jsonl")
        assert [e.op for e in entries] == ["init", "put"]

    def test_export_unknown_ulid_fails(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        with pytest.raises(SignatureError):
            fresh_vault.export(new_ulid(), r.fingerprint)
        # Audit log must not contain export line.
        entries = verify_chain(fresh_vault.root / "audit_log.jsonl")
        assert [e.op for e in entries] == ["init"]

    def test_two_exports_have_different_blobs(self, fresh_vault: Vault) -> None:
        """Two exports of the same entry to the same recipient produce
        different blobs (fresh KEM encap + fresh AES-GCM nonce each time)."""
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"same content", name="x")
        b1 = fresh_vault.export(meta.ulid, r.fingerprint)
        b2 = fresh_vault.export(meta.ulid, r.fingerprint)
        assert b1 != b2  # nondeterministic encap


class TestExportBundleVerification:
    def test_tampered_blob_b64_rejected(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        doc = json.loads(bundle_bytes)
        # Flip a single base64 char in the blob.
        original = doc["blob"]
        doc["blob"] = "A" + original[1:] if original[0] != "A" else "B" + original[1:]
        with pytest.raises(SignatureError):
            open_export_bundle(canonicalize(doc), recipient_kem)  # type: ignore[arg-type]

    def test_tampered_size_rejected(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        doc = json.loads(bundle_bytes)
        doc["size"] = doc["size"] + 1
        with pytest.raises(SignatureError):
            open_export_bundle(canonicalize(doc), recipient_kem)  # type: ignore[arg-type]

    def test_tampered_name_rejected(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="orig.txt")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        doc = json.loads(bundle_bytes)
        doc["name"] = "rewritten.txt"
        with pytest.raises(SignatureError):
            open_export_bundle(canonicalize(doc), recipient_kem)  # type: ignore[arg-type]

    def test_tampered_blob_sha256_rejected(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        doc = json.loads(bundle_bytes)
        doc["blob_sha256"] = "0" * 64
        with pytest.raises(SignatureError):
            open_export_bundle(canonicalize(doc), recipient_kem)  # type: ignore[arg-type]

    def test_truncated_signature_rejected(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        doc = json.loads(bundle_bytes)
        original_sig = doc["sig_hybrid"]
        doc["sig_hybrid"] = original_sig[:-4]  # snip 4 chars (~3 bytes raw)
        with pytest.raises((SignatureError, SchemaValidationError)):
            open_export_bundle(canonicalize(doc), recipient_kem)  # type: ignore[arg-type]

    def test_swapped_sender_pk_rejected(self, fresh_vault: Vault) -> None:
        """Replacing sender_sig_pk with someone else's pubkey must fail
        (the sig won't verify under it)."""
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        doc = json.loads(bundle_bytes)
        # Replace sender_sig_pk with a fresh, unrelated pubkey.
        attacker_sig = generate_sig_keypair()
        doc["sender_sig_pk"] = base64.b64encode(attacker_sig.public_bytes()).decode("ascii")
        with pytest.raises(SignatureError):
            open_export_bundle(canonicalize(doc), recipient_kem)  # type: ignore[arg-type]

    def test_missing_required_field_rejected(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        doc = json.loads(bundle_bytes)
        del doc["recipient_fingerprint"]
        with pytest.raises(SchemaValidationError):
            open_export_bundle(canonicalize(doc), recipient_kem)  # type: ignore[arg-type]


class TestExportRecipientCheck:
    def test_expected_sender_match_passes(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        sender_pk = fresh_vault.identity.sig.public_bytes()
        plaintext, _ = open_export_bundle(
            bundle_bytes,
            recipient_kem,  # type: ignore[arg-type]
            expected_sender_sig_pk=sender_pk,
        )
        assert plaintext == b"hello"

    def test_expected_sender_mismatch_rejected(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        attacker_sig = generate_sig_keypair()
        with pytest.raises(SignatureError):
            open_export_bundle(
                bundle_bytes,
                recipient_kem,  # type: ignore[arg-type]
                expected_sender_sig_pk=attacker_sig.public_bytes(),
            )

    def test_expected_fingerprint_match_passes(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        plaintext, _ = open_export_bundle(
            bundle_bytes,
            recipient_kem,  # type: ignore[arg-type]
            expected_recipient_fingerprint=r.fingerprint,
        )
        assert plaintext == b"hello"

    def test_expected_fingerprint_mismatch_rejected(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, recipient_kem, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        with pytest.raises(SignatureError):
            open_export_bundle(
                bundle_bytes,
                recipient_kem,  # type: ignore[arg-type]
                expected_recipient_fingerprint="0" * 32,
            )


class TestExportWrongRecipient:
    def test_export_to_alice_cannot_be_opened_by_bob(self, fresh_vault: Vault) -> None:
        # Two unrelated recipients.
        kem_a, sig_a, kem_a_kp, _ = _make_recipient_keys()
        _, _, kem_b_kp, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_a, sig_pk=sig_a, label="alice")
        meta = fresh_vault.put(b"private", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        # Alice can open it.
        plaintext, _ = open_export_bundle(bundle_bytes, kem_a_kp)  # type: ignore[arg-type]
        assert plaintext == b"private"
        # Bob (different KEM keypair) cannot.
        with pytest.raises(SignatureError):
            open_export_bundle(bundle_bytes, kem_b_kp)  # type: ignore[arg-type]


class TestExportBundleStructure:
    def test_bundle_is_canonical_json(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hi", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        # Re-canonicalizing the parsed JSON must produce identical bytes.
        doc = json.loads(bundle_bytes)
        assert canonicalize(doc) == bundle_bytes

    def test_bundle_has_domain_separator_in_signature(self, fresh_vault: Vault) -> None:
        """Sanity: EXPORT_SIG_DOMAIN constant has the documented value."""
        assert EXPORT_SIG_DOMAIN == b"qwashed/vault/v0.1/export-bundle"

    def test_bundle_keys_set(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hi", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        doc = json.loads(bundle_bytes)
        assert set(doc.keys()) == {
            "blob",
            "blob_sha256",
            "exported_at",
            "name",
            "recipient_fingerprint",
            "sender_sig_pk",
            "sig_hybrid",
            "size",
            "ulid",
            "version",
        }


class TestExportAuditLogIntegration:
    def test_full_chain_with_init_put_export(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        m1 = fresh_vault.put(b"a", name="a")
        m2 = fresh_vault.put(b"b", name="b")
        fresh_vault.export(m1.ulid, r.fingerprint)
        fresh_vault.export(m2.ulid, r.fingerprint)
        entries = verify_chain(fresh_vault.root / "audit_log.jsonl")
        ops = [e.op for e in entries]
        assert ops == ["init", "put", "put", "export", "export"]
        export_subjects = [e.subject for e in entries if e.op == "export"]
        assert export_subjects == [
            f"{m1.ulid}|to={r.fingerprint}",
            f"{m2.ulid}|to={r.fingerprint}",
        ]

    def test_export_does_not_break_verify(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hello", name="x")
        fresh_vault.export(meta.ulid, r.fingerprint)
        # The vault's own verify() must still pass: export writes nothing
        # to entries/ and only appends to audit log.
        fresh_vault.verify()


class TestRecipientDataclass:
    def test_recipient_to_dict_canonical(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        assert isinstance(r, Recipient)
        d = r.to_dict()
        assert d == {
            "added_at": r.added_at,
            "fingerprint": r.fingerprint,
            "kem_pk": r.kem_pk_b64,
            "label": "alice",
            "sig_pk": r.sig_pk_b64,
            "version": RECIPIENT_VERSION,
        }


class TestExportBundleDataclass:
    def test_bundle_to_dict_with_and_without_signature(self, fresh_vault: Vault) -> None:
        kem_pub, sig_pub, _, _ = _make_recipient_keys()
        r = fresh_vault.add_recipient(kem_pk=kem_pub, sig_pk=sig_pub, label="alice")
        meta = fresh_vault.put(b"hi", name="x")
        bundle_bytes = fresh_vault.export(meta.ulid, r.fingerprint)
        # Round-trip through ExportBundle dataclass.
        from qwashed.vault.store import _parse_export_bundle

        bundle = _parse_export_bundle(bundle_bytes)
        assert isinstance(bundle, ExportBundle)
        with_sig = bundle.to_dict(with_signature=True)
        no_sig = bundle.to_dict(with_signature=False)
        assert "sig_hybrid" in with_sig
        assert "sig_hybrid" not in no_sig
        assert {k: v for k, v in with_sig.items() if k != "sig_hybrid"} == no_sig
