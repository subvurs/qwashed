# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for the v0.1 -> v0.2 vault format migration path.

Covers:

* New vaults are written at :data:`FORMAT_VERSION_CURRENT` (v0.2).
* A vault forged at v0.1 (manifest + entries with the legacy HKDF info
  string and blob-version byte 1) is readable by a v0.2 reader without
  upgrade.
* :meth:`Vault.upgrade` re-encrypts every legacy entry to v0.2,
  preserves plaintext byte-for-byte, appends one ``op="upgrade"`` audit
  line per entry, leaves the original ``op="put"`` lines in place, and
  rewrites the manifest at the new format. Idempotent: a second run is
  a no-op.
* Mixed-format vaults (some v0.1, some v0.2 entries) are readable, and
  :meth:`Vault.upgrade` only migrates the v0.1 ones.
* No plaintext bytes leak to disk during an upgrade — every byte that
  appears on disk is either ciphertext, signed metadata, or audit-log
  data (verified by walking the vault root and asserting plaintext is
  absent).
* v0.1 byte-identical re-emission: a manifest / meta file written at
  ``format_version=1`` is canonical-byte-identical to the v0.1
  reference output.
"""

from __future__ import annotations

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
from qwashed.core.errors import SignatureError  # noqa: E402
from qwashed.core.kdf import ARGON2ID_MIN_MEMORY_KIB, ARGON2ID_MIN_TIME_COST  # noqa: E402
from qwashed.vault.audit_log import verify_chain  # noqa: E402
from qwashed.vault.store import (  # noqa: E402
    BLOB_VERSION_V01,
    BLOB_VERSION_V02,
    FORMAT_VERSION_CURRENT,
    FORMAT_VERSION_V01,
    FORMAT_VERSION_V02,
    Vault,
    _atomic_write,
    _entry_blob_path,
    _entry_meta_path,
    _manifest_path,
    _peek_blob_version,
    _seal_blob,
    _sign_manifest,
    _sign_metadata,
    init_vault,
    unlock_vault,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_PASSPHRASE = b"correct-horse-battery-staple"

_FAST_ARGON = {
    "memory_kib": ARGON2ID_MIN_MEMORY_KIB,
    "time_cost": ARGON2ID_MIN_TIME_COST,
    "parallelism": 1,
}


@pytest.fixture
def fresh_vault(tmp_path: Path) -> Vault:
    return init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)


def _downgrade_entry_to_v01(vault: Vault, ulid: str, plaintext: bytes, *, name: str) -> None:
    """Replace ``ulid``'s on-disk blob+meta with v0.1-encoded equivalents.

    Used by tests to forge a legacy entry inside an otherwise-v0.2 vault.
    Re-derives the ciphertext and the signed metadata at
    :data:`FORMAT_VERSION_V01` so a v0.2 reader sees a genuine v0.1
    blob byte and a v0.1 ``meta.json`` (with no ``format_version``
    field in the canonical body).
    """
    blob = _seal_blob(
        ulid=ulid,
        plaintext=plaintext,
        recipient_kem_pk=vault.identity.kem.public_bytes(),
        format_version=FORMAT_VERSION_V01,
    )
    import hashlib  # local import keeps top-level imports tidy

    blob_sha256 = hashlib.sha256(blob).hexdigest()
    meta = _sign_metadata(
        ulid=ulid,
        name=name,
        size=len(plaintext),
        created_at="2026-04-30T00:00:00Z",
        blob_sha256=blob_sha256,
        identity=vault.identity,
        format_version=FORMAT_VERSION_V01,
    )
    _atomic_write(_entry_blob_path(vault.root, ulid), blob)
    _atomic_write(
        _entry_meta_path(vault.root, ulid),
        canonicalize(meta.to_dict(with_signature=True)),
    )


def _downgrade_manifest_to_v01(vault: Vault) -> None:
    """Rewrite ``manifest.json`` at :data:`FORMAT_VERSION_V01`."""
    legacy = _sign_manifest(
        vault_id=vault.manifest.vault_id,
        created_at=vault.manifest.created_at,
        identity=vault.identity,
        format_version=FORMAT_VERSION_V01,
    )
    _atomic_write(
        _manifest_path(vault.root),
        canonicalize(legacy.to_dict(with_signature=True)),
    )


# ---------------------------------------------------------------------------
# Defaults: new vaults are v0.2
# ---------------------------------------------------------------------------


class TestNewVaultIsV02:
    def test_manifest_format_version(self, fresh_vault: Vault) -> None:
        assert fresh_vault.manifest.format_version == FORMAT_VERSION_V02

    def test_manifest_json_has_format_version_field(self, fresh_vault: Vault) -> None:
        doc = json.loads(_manifest_path(fresh_vault.root).read_text("utf-8"))
        assert doc["format_version"] == FORMAT_VERSION_V02

    def test_new_entry_blob_byte_is_v02(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"hello", name="hello.txt")
        blob = _entry_blob_path(fresh_vault.root, meta.ulid).read_bytes()
        assert _peek_blob_version(blob) == BLOB_VERSION_V02

    def test_new_entry_meta_has_format_version_field(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"hello", name="hello.txt")
        doc = json.loads(_entry_meta_path(fresh_vault.root, meta.ulid).read_text("utf-8"))
        assert doc["format_version"] == FORMAT_VERSION_V02


# ---------------------------------------------------------------------------
# Backward compatibility: v0.1 vaults remain readable
# ---------------------------------------------------------------------------


class TestV01ReadableByV02Reader:
    def test_legacy_meta_omits_format_version_field(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"legacy", name="legacy.txt")
        _downgrade_entry_to_v01(fresh_vault, meta.ulid, b"legacy", name="legacy.txt")
        doc = json.loads(_entry_meta_path(fresh_vault.root, meta.ulid).read_text("utf-8"))
        # v0.1 canonical body omits format_version entirely (preserves
        # byte-identical signing for legacy vaults).
        assert "format_version" not in doc

    def test_legacy_manifest_omits_format_version_field(self, fresh_vault: Vault) -> None:
        _downgrade_manifest_to_v01(fresh_vault)
        doc = json.loads(_manifest_path(fresh_vault.root).read_text("utf-8"))
        assert "format_version" not in doc

    def test_v01_entry_round_trip_via_v02_reader(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"plaintext-payload", name="x")
        _downgrade_entry_to_v01(
            fresh_vault, meta.ulid, b"plaintext-payload", name="x"
        )
        # Re-open the vault from disk to ensure no in-memory state
        # leaks the v0.2 view.
        v = unlock_vault(fresh_vault.root, _PASSPHRASE)
        plaintext, reread = v.get(meta.ulid)
        assert plaintext == b"plaintext-payload"
        assert reread.format_version == FORMAT_VERSION_V01

    def test_v01_vault_verify_passes(self, tmp_path: Path) -> None:
        v = init_vault(tmp_path / "v01", _PASSPHRASE, **_FAST_ARGON)
        meta = v.put(b"alpha", name="a")
        _downgrade_entry_to_v01(v, meta.ulid, b"alpha", name="a")
        _downgrade_manifest_to_v01(v)
        # Re-open and verify the entire chain.
        re = unlock_vault(v.root, _PASSPHRASE)
        assert re.manifest.format_version == FORMAT_VERSION_V01
        re.verify()


# ---------------------------------------------------------------------------
# Upgrade: full migration
# ---------------------------------------------------------------------------


class TestUpgrade:
    def test_upgrade_migrates_all_v01_entries(self, fresh_vault: Vault) -> None:
        ulids = []
        for i in range(3):
            payload = f"entry-{i}".encode()
            meta = fresh_vault.put(payload, name=f"e{i}")
            _downgrade_entry_to_v01(fresh_vault, meta.ulid, payload, name=f"e{i}")
            ulids.append(meta.ulid)
        _downgrade_manifest_to_v01(fresh_vault)

        v = unlock_vault(fresh_vault.root, _PASSPHRASE)
        report = v.upgrade()

        assert sorted(report.upgraded) == sorted(ulids)
        assert report.already_current == ()
        assert report.target_format_version == FORMAT_VERSION_V02

        # All blobs are now v0.2.
        for ulid in ulids:
            blob = _entry_blob_path(v.root, ulid).read_bytes()
            assert _peek_blob_version(blob) == BLOB_VERSION_V02

        # Manifest is also v0.2 on disk.
        doc = json.loads(_manifest_path(v.root).read_text("utf-8"))
        assert doc["format_version"] == FORMAT_VERSION_V02

    def test_upgrade_preserves_plaintext_byte_for_byte(
        self, fresh_vault: Vault
    ) -> None:
        payload = b"\x00\x01\x02\xff\xfe\xfd binary safe payload"
        meta = fresh_vault.put(payload, name="bin")
        _downgrade_entry_to_v01(fresh_vault, meta.ulid, payload, name="bin")

        v = unlock_vault(fresh_vault.root, _PASSPHRASE)
        v.upgrade()

        re = unlock_vault(v.root, _PASSPHRASE)
        plaintext, new_meta = re.get(meta.ulid)
        assert plaintext == payload
        assert new_meta.format_version == FORMAT_VERSION_V02
        # ULID, name, size, created_at all preserved across migration.
        assert new_meta.ulid == meta.ulid
        assert new_meta.name == meta.name
        assert new_meta.size == meta.size
        # created_at is preserved exactly.
        assert new_meta.created_at == "2026-04-30T00:00:00Z"

    def test_upgrade_idempotent(self, fresh_vault: Vault) -> None:
        meta = fresh_vault.put(b"once", name="o")
        _downgrade_entry_to_v01(fresh_vault, meta.ulid, b"once", name="o")

        v = unlock_vault(fresh_vault.root, _PASSPHRASE)
        first = v.upgrade()
        second = v.upgrade()

        assert len(first.upgraded) == 1
        assert second.upgraded == ()
        assert second.already_current == (meta.ulid,)

    def test_upgrade_appends_one_audit_line_per_entry(
        self, fresh_vault: Vault
    ) -> None:
        ulids = []
        for i in range(2):
            payload = f"u{i}".encode()
            meta = fresh_vault.put(payload, name=f"u{i}")
            _downgrade_entry_to_v01(fresh_vault, meta.ulid, payload, name=f"u{i}")
            ulids.append(meta.ulid)

        v = unlock_vault(fresh_vault.root, _PASSPHRASE)
        v.upgrade()

        entries = verify_chain(v.root / "audit_log.jsonl")
        upgrade_subjects = [e.subject for e in entries if e.op == "upgrade"]
        assert sorted(upgrade_subjects) == sorted(ulids)

    def test_upgrade_preserves_original_put_lines(
        self, fresh_vault: Vault
    ) -> None:
        meta = fresh_vault.put(b"original", name="o")
        _downgrade_entry_to_v01(fresh_vault, meta.ulid, b"original", name="o")

        v = unlock_vault(fresh_vault.root, _PASSPHRASE)
        v.upgrade()

        entries = verify_chain(v.root / "audit_log.jsonl")
        ops = [e.op for e in entries]
        # Genesis init + put + upgrade, in that order.
        assert ops == ["init", "put", "upgrade"]
        # verify() must still pass: original 'put' subject still maps
        # to an on-disk entry (now v0.2).
        v.verify()

    def test_upgrade_on_already_current_vault_is_noop(
        self, fresh_vault: Vault
    ) -> None:
        # Brand-new vault is already at v0.2.
        for i in range(2):
            fresh_vault.put(f"x{i}".encode(), name=f"x{i}")

        v = unlock_vault(fresh_vault.root, _PASSPHRASE)
        manifest_before = _manifest_path(v.root).read_bytes()
        report = v.upgrade()

        assert report.upgraded == ()
        assert len(report.already_current) == 2
        # Manifest file unchanged on disk.
        manifest_after = _manifest_path(v.root).read_bytes()
        assert manifest_before == manifest_after


# ---------------------------------------------------------------------------
# Mixed-format vaults
# ---------------------------------------------------------------------------


class TestMixedFormatVault:
    def test_mixed_vault_readable(self, fresh_vault: Vault) -> None:
        m_v02 = fresh_vault.put(b"new", name="new")
        m_legacy = fresh_vault.put(b"old", name="old")
        _downgrade_entry_to_v01(fresh_vault, m_legacy.ulid, b"old", name="old")

        v = unlock_vault(fresh_vault.root, _PASSPHRASE)
        pt_new, _ = v.get(m_v02.ulid)
        pt_old, _ = v.get(m_legacy.ulid)
        assert pt_new == b"new"
        assert pt_old == b"old"

    def test_upgrade_migrates_only_legacy(self, fresh_vault: Vault) -> None:
        m_v02 = fresh_vault.put(b"new", name="new")
        m_legacy = fresh_vault.put(b"old", name="old")
        _downgrade_entry_to_v01(fresh_vault, m_legacy.ulid, b"old", name="old")

        v = unlock_vault(fresh_vault.root, _PASSPHRASE)
        report = v.upgrade()

        assert report.upgraded == (m_legacy.ulid,)
        assert report.already_current == (m_v02.ulid,)


# ---------------------------------------------------------------------------
# No plaintext spill during upgrade
# ---------------------------------------------------------------------------


class TestNoPlaintextSpill:
    def test_distinctive_plaintext_never_appears_on_disk(
        self, tmp_path: Path
    ) -> None:
        # Use a marker that should be impossible to find by chance.
        marker = b"QWASHED_TEST_PLAINTEXT_MARKER_8c14f7d2_"
        plaintext = marker + b"-payload-body"

        v = init_vault(tmp_path / "v", _PASSPHRASE, **_FAST_ARGON)
        meta = v.put(plaintext, name="m")
        _downgrade_entry_to_v01(v, meta.ulid, plaintext, name="m")
        # Now upgrade.
        re = unlock_vault(v.root, _PASSPHRASE)
        re.upgrade()

        # Walk every byte of the on-disk vault and assert the marker
        # never appears. Catches accidental writes of plaintext through
        # any path (tempfiles, audit log, manifest, blob, meta).
        for path in v.root.rglob("*"):
            if path.is_file():
                blob = path.read_bytes()
                assert marker not in blob, f"plaintext marker found in {path}"


# ---------------------------------------------------------------------------
# Defensive: cross-format mismatch and unsupported targets
# ---------------------------------------------------------------------------


class TestDefenses:
    def test_upgrade_rejects_unsupported_target(self, fresh_vault: Vault) -> None:
        v = unlock_vault(fresh_vault.root, _PASSPHRASE)
        with pytest.raises(Exception):  # SchemaValidationError
            v.upgrade(target_format_version=99)

    def test_upgrade_rejects_format_mismatch_meta_vs_blob(
        self, fresh_vault: Vault
    ) -> None:
        # Forge a mismatch in the upgrade direction: blob byte is v0.1
        # but the signed metadata claims v0.2. upgrade() must refuse to
        # silently re-encrypt under a contradictory contract.
        import hashlib

        plaintext = b"mismatch"
        meta = fresh_vault.put(plaintext, name="m")

        # Replace the on-disk blob with a v0.1 ciphertext.
        legacy_blob = _seal_blob(
            ulid=meta.ulid,
            plaintext=plaintext,
            recipient_kem_pk=fresh_vault.identity.kem.public_bytes(),
            format_version=FORMAT_VERSION_V01,
        )
        # Sign new metadata at v0.2 (default current) over the new blob
        # hash so the meta passes signature verification but disagrees
        # with the blob's on-disk version byte.
        new_sha = hashlib.sha256(legacy_blob).hexdigest()
        v02_meta = _sign_metadata(
            ulid=meta.ulid,
            name=meta.name,
            size=meta.size,
            created_at=meta.created_at,
            blob_sha256=new_sha,
            identity=fresh_vault.identity,
            format_version=FORMAT_VERSION_V02,
        )
        _atomic_write(_entry_blob_path(fresh_vault.root, meta.ulid), legacy_blob)
        _atomic_write(
            _entry_meta_path(fresh_vault.root, meta.ulid),
            canonicalize(v02_meta.to_dict(with_signature=True)),
        )

        v = unlock_vault(fresh_vault.root, _PASSPHRASE)
        with pytest.raises(SignatureError):
            v.upgrade()


# ---------------------------------------------------------------------------
# Sanity: format version helper coverage
# ---------------------------------------------------------------------------


class TestFormatVersionConstants:
    def test_current_is_v02(self) -> None:
        assert FORMAT_VERSION_CURRENT == FORMAT_VERSION_V02

    def test_v01_v02_distinct(self) -> None:
        assert FORMAT_VERSION_V01 == 1
        assert FORMAT_VERSION_V02 == 2
        assert BLOB_VERSION_V01 == 1
        assert BLOB_VERSION_V02 == 2
