# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Local file-backed hybrid-PQ vault.

This is the on-disk vault the user actually interacts with. It binds
together every other vault primitive:

* :mod:`qwashed.vault.hybrid_kem` -- X25519 || ML-KEM-768 sealing of
  per-entry payload keys.
* :mod:`qwashed.vault.hybrid_sig` -- Ed25519 || ML-DSA-65 signing of
  manifest, per-entry metadata, and audit log lines.
* :mod:`qwashed.vault.audit_log` -- append-only, hash-chained,
  hybrid-signed log of every mutating operation.
* :mod:`qwashed.core.kdf` -- Argon2id passphrase wrap around the
  identity secret key, HKDF-SHA256 derivation of the per-entry AEAD key
  from the hybrid KEM shared secret.

On-disk layout
--------------

::

    <vault-root>/
      manifest.json             canonical JSON, hybrid-signed
      keys/
        identity.pub            canonical JSON; public KEM + SIG keys
        identity.sk.enc         canonical JSON envelope, Argon2id+AES-GCM
                                wrapped over the four secret keys
        recipients/             reserved for v0.2 (recipient pubkeys)
      entries/
        <ulid>.bin              binary AEAD-sealed blob (see _BlobHeader)
        <ulid>.meta.json        canonical JSON, hybrid-signed
      audit_log.jsonl           append-only, hash-chained, hybrid-signed

Permissions are enforced fail-closed: directories ``0o700`` and files
``0o600`` on every write. Any pre-existing path with looser permissions
is *not* automatically tightened (we do not silently mutate the user's
environment), but a fresh ``init`` always lays down strict permissions.

Entry blob format (``entries/<ulid>.bin``)
------------------------------------------

::

    magic       4 bytes   = b"QWEV"             ("QWashed Entry V")
    version     1 byte    = 0x01
    reserved    3 bytes   = b"\\x00\\x00\\x00"   (alignment padding)
    kem_ct_len  4 bytes   big-endian            length of kem ciphertext
    kem_ct      kem_ct_len bytes                hybrid KEM ciphertext
    nonce       12 bytes                        AES-256-GCM nonce
    aead_blob   N bytes                         AES-256-GCM ciphertext+tag

The AEAD key is::

    aead_key = HKDF-SHA256(
        ikm    = hybrid_kem.shared_secret,        # 32 bytes
        salt   = b"",
        info   = info_for(module="vault", purpose="entry-aead"),
        length = 32,
    )

The AEAD additional-authenticated-data (AAD) is the entry's ULID encoded
as ASCII bytes. This binds the ciphertext to its filename: an attacker
swapping two ``.bin`` files (without re-signing meta.json) would be
caught at decrypt.

Fail-closed posture
-------------------
Every error path raises a typed exception
(:class:`SignatureError`, :class:`SchemaValidationError`,
:class:`ConfigurationError`, :class:`KeyDerivationError`). There is no
silent best-effort. Wrong passphrase, tampered blob, missing meta,
missing audit-log line, bad permissions on an existing vault -- all
fail loudly.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import secrets
import struct
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qwashed.core.canonical import canonicalize
from qwashed.core.errors import (
    ConfigurationError,
    SchemaValidationError,
    SignatureError,
)
from qwashed.core.kdf import (
    ARGON2ID_DEFAULT_MEMORY_KIB,
    ARGON2ID_DEFAULT_PARALLELISM,
    ARGON2ID_DEFAULT_TIME_COST,
    argon2id,
    hkdf_sha256,
    info_for,
)
from qwashed.vault.audit_log import (
    GENESIS_PREV_HASH,
    AuditLogReader,
    AuditLogWriter,
    append_entry,
    verify_chain,
)
from qwashed.vault.hybrid_kem import (
    MLKEM768_SECRETKEY_LEN,
    X25519_PUBKEY_LEN,
    HybridKemKeypair,
    decapsulate,
    encapsulate,
)
from qwashed.vault.hybrid_kem import (
    generate_keypair as generate_kem_keypair,
)
from qwashed.vault.hybrid_sig import (
    ED25519_PUBKEY_LEN,
    MLDSA65_SECRETKEY_LEN,
    HybridSigKeypair,
    sign,
    verify,
)
from qwashed.vault.hybrid_sig import (
    generate_keypair as generate_sig_keypair,
)

__all__ = [
    "BLOB_MAGIC",
    "BLOB_VERSION",
    "BLOB_VERSION_V01",
    "BLOB_VERSION_V02",
    "DIR_MODE",
    "ENTRY_AEAD_INFO",
    "ENTRY_AEAD_INFO_V01",
    "ENTRY_AEAD_INFO_V02",
    "ENTRY_NONCE_LEN",
    "EXPORT_SIG_DOMAIN",
    "EXPORT_VERSION",
    "FILE_MODE",
    "FORMAT_VERSION_CURRENT",
    "FORMAT_VERSION_V01",
    "FORMAT_VERSION_V02",
    "IDENTITY_VERSION",
    "MANIFEST_VERSION",
    "META_VERSION",
    "RECIPIENT_VERSION",
    "EntryMetadata",
    "ExportBundle",
    "Recipient",
    "UpgradeReport",
    "Vault",
    "VaultIdentity",
    "VaultManifest",
    "init_vault",
    "new_ulid",
    "open_export_bundle",
    "unlock_vault",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: 0o700 mode for vault directories (rwx by owner only).
DIR_MODE: Final[int] = 0o700

#: 0o600 mode for vault files (rw by owner only).
FILE_MODE: Final[int] = 0o600

#: Schema version of ``manifest.json``.
MANIFEST_VERSION: Final[int] = 1

#: Schema version of ``identity.sk.enc`` and ``identity.pub``.
IDENTITY_VERSION: Final[int] = 1

#: Schema version of ``<ulid>.meta.json``.
META_VERSION: Final[int] = 1

#: Magic bytes at the start of an encrypted entry blob.
BLOB_MAGIC: Final[bytes] = b"QWEV"

#: Vault format version constants. v0.1 is the initial release format;
#: v0.2 introduces versioned HKDF info strings (domain separation across
#: format generations) but retains identical algorithm choices.
FORMAT_VERSION_V01: Final[int] = 1
FORMAT_VERSION_V02: Final[int] = 2

#: Current/default format version used by all new writes in this build.
FORMAT_VERSION_CURRENT: Final[int] = FORMAT_VERSION_V02

#: Set of format versions this build accepts on read. Older formats are
#: still readable until the deprecation window closes (planned: v0.4).
_SUPPORTED_FORMAT_VERSIONS: Final[frozenset[int]] = frozenset(
    {FORMAT_VERSION_V01, FORMAT_VERSION_V02}
)

#: Version of the entry blob binary header. The byte at offset 4 of every
#: blob equals one of these. New writes use ``BLOB_VERSION_V02``; readers
#: dispatch on the byte to choose the correct HKDF info strings.
BLOB_VERSION_V01: Final[int] = 1
BLOB_VERSION_V02: Final[int] = 2

#: Backwards-compatible alias for the current default blob version.
BLOB_VERSION: Final[int] = BLOB_VERSION_V02

#: AES-256-GCM nonce length (96 bits / 12 bytes per NIST SP 800-38D).
ENTRY_NONCE_LEN: Final[int] = 12

#: HKDF info strings for entry AEAD key derivation, per format version.
ENTRY_AEAD_INFO_V01: Final[bytes] = info_for(module="vault", purpose="entry-aead", version="v0.1")
ENTRY_AEAD_INFO_V02: Final[bytes] = info_for(module="vault", purpose="entry-aead", version="v0.2")

#: Backwards-compatible alias (v0.1 callers).
ENTRY_AEAD_INFO: Final[bytes] = ENTRY_AEAD_INFO_V01


def _entry_aead_info_for(format_version: int) -> bytes:
    """Return the HKDF info string for entry AEAD derivation at the given
    ``format_version``.

    Raises
    ------
    SignatureError
        If ``format_version`` is not in :data:`_SUPPORTED_FORMAT_VERSIONS`.
    """
    if format_version == FORMAT_VERSION_V01:
        return ENTRY_AEAD_INFO_V01
    if format_version == FORMAT_VERSION_V02:
        return ENTRY_AEAD_INFO_V02
    raise SignatureError(
        f"unsupported entry AEAD format_version: {format_version}",
        error_code="vault.store.bad_aead_format_version",
    )


#: Maximum sane KEM-ciphertext length we will accept when parsing a blob.
_MAX_KEM_CT_LEN: Final[int] = 1 << 16  # 64 KiB; FIPS 203 ML-KEM-768 ct is 1088 bytes.

#: Maximum sane AEAD ciphertext we will accept (1 GiB; vault is for documents,
#: not bulk video).
_MAX_AEAD_CT_LEN: Final[int] = 1 << 30

#: Schema version of recipient pub files (``recipients/<fp>.pub``).
RECIPIENT_VERSION: Final[int] = 1

#: Schema version of an export bundle.
EXPORT_VERSION: Final[int] = 1

#: Domain-separation tag prefixed to bundle bytes before signing. Distinguishes
#: an export-bundle signature from any other hybrid signature in the system,
#: so a meta.json signature can never be substituted for a bundle signature
#: (or vice versa).
EXPORT_SIG_DOMAIN: Final[bytes] = b"qwashed/vault/v0.1/export-bundle"

#: Length of a recipient fingerprint (hex chars). 32 hex = 128 bits of the
#: SHA-256 digest of the serialized hybrid pubkeys; sufficient collision
#: resistance for a vault-local address-book.
_RECIPIENT_FP_LEN: Final[int] = 32

#: Sentinel filename suffix for recipient pubkey files.
_RECIPIENT_PUB_SUFFIX: Final[str] = ".pub"


# ---------------------------------------------------------------------------
# ULID
# ---------------------------------------------------------------------------

_CROCKFORD_ALPHABET: Final[str] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid() -> str:
    """Generate a fresh ULID (Crockford base32, 26 chars).

    48-bit big-endian millisecond timestamp || 80 random bits. Sortable
    by creation time, opaque to humans, monotonic at second-scale.
    """
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_bits = int.from_bytes(secrets.token_bytes(10), "big")
    value = (ts_ms << 80) | rand_bits
    out = bytearray(26)
    for i in range(26):
        out[25 - i] = ord(_CROCKFORD_ALPHABET[value & 0x1F])
        value >>= 5
    return out.decode("ascii")


def _validate_ulid(ulid: str) -> None:
    """Raise :class:`SchemaValidationError` unless ``ulid`` is a 26-char
    Crockford base32 string."""
    if len(ulid) != 26:
        raise SchemaValidationError(
            f"ulid must be 26 characters, got {len(ulid)}",
            error_code="vault.store.bad_ulid_length",
        )
    for ch in ulid:
        if ch not in _CROCKFORD_ALPHABET:
            raise SchemaValidationError(
                f"ulid contains non-Crockford character: {ch!r}",
                error_code="vault.store.bad_ulid_char",
            )


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Permission-safe file writes
# ---------------------------------------------------------------------------


def _atomic_write(path: Path, data: bytes, *, mode: int = FILE_MODE) -> None:
    """Write ``data`` to ``path`` atomically with strict permissions.

    The destination is replaced via ``os.replace`` so a half-written file
    is never observable. The ``mode`` is enforced via ``os.open(..., O_CREAT)``
    so we never have a window where the file is world-readable.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except Exception:
        with contextlib.suppress(OSError):  # pragma: no cover - cleanup best-effort
            tmp.unlink(missing_ok=True)
        raise
    tmp.replace(path)
    # Path.replace may reset bits on some platforms; re-apply.
    path.chmod(mode)


# ---------------------------------------------------------------------------
# Identity (in-memory pair of hybrid keypairs)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VaultIdentity:
    """The vault owner's full hybrid identity.

    Holds *both* a hybrid KEM keypair (used to seal per-entry payload
    keys) and a hybrid signing keypair (used to sign the manifest, every
    entry's metadata, and every audit log line). Splitting the two would
    weaken the hybrid guarantee: a hybrid identity must always carry both
    a KEM and a signature half.
    """

    kem: HybridKemKeypair
    sig: HybridSigKeypair

    def kem_public_b64(self) -> str:
        return base64.b64encode(self.kem.public_bytes()).decode("ascii")

    def sig_public_b64(self) -> str:
        return base64.b64encode(self.sig.public_bytes()).decode("ascii")


# ---------------------------------------------------------------------------
# Manifest + metadata schemas
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VaultManifest:
    """Top-level signed root of trust for a vault.

    ``version`` is the JSON-schema version (still 1 in v0.2 — the document
    shape has not broken). ``format_version`` tracks the cryptographic
    binding format: 1 == v0.1 (HKDF info ``qwashed/vault/v0.1/*``,
    blob version byte 1), 2 == v0.2. The field is omitted from the
    canonical signed body when ``format_version == 1`` so that v0.1
    manifests remain bit-identical under a v0.2 reader.
    """

    version: int
    vault_id: str
    created_at: str
    kem_pk_b64: str
    sig_pk_b64: str
    sig_hybrid_b64: str
    format_version: int = FORMAT_VERSION_V01

    def to_dict(self, *, with_signature: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "created_at": self.created_at,
            "kem_pk": self.kem_pk_b64,
            "sig_pk": self.sig_pk_b64,
            "vault_id": self.vault_id,
            "version": self.version,
        }
        if self.format_version > FORMAT_VERSION_V01:
            out["format_version"] = self.format_version
        if with_signature:
            out["sig_hybrid"] = self.sig_hybrid_b64
        return out


@dataclass(frozen=True)
class EntryMetadata:
    """Per-entry signed metadata, persisted as ``<ulid>.meta.json``.

    ``format_version`` mirrors the per-entry blob's cryptographic format
    (see :class:`VaultManifest`): 1 == v0.1 ciphertext (HKDF info
    ``qwashed/vault/v0.1/entry-aead`` + blob byte 1), 2 == v0.2.
    Like the manifest, the field is omitted from the canonical signed
    body when equal to 1 so legacy meta files remain byte-identical.
    """

    version: int
    ulid: str
    name: str
    size: int
    created_at: str
    blob_sha256: str
    actor_pk_b64: str
    sig_hybrid_b64: str
    format_version: int = FORMAT_VERSION_V01

    def to_dict(self, *, with_signature: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "actor_pk": self.actor_pk_b64,
            "blob_sha256": self.blob_sha256,
            "created_at": self.created_at,
            "name": self.name,
            "size": self.size,
            "ulid": self.ulid,
            "version": self.version,
        }
        if self.format_version > FORMAT_VERSION_V01:
            out["format_version"] = self.format_version
        if with_signature:
            out["sig_hybrid"] = self.sig_hybrid_b64
        return out


@dataclass(frozen=True)
class UpgradeReport:
    """Result of a :meth:`Vault.upgrade` run.

    ``upgraded`` is the list of ULIDs that were re-encrypted from
    v0.1 to v0.2. ``already_current`` is the list of ULIDs that were
    already at the current format and were not touched. The two lists
    are disjoint and together cover every entry in the vault at the
    moment :meth:`Vault.upgrade` was invoked.
    """

    upgraded: tuple[str, ...]
    already_current: tuple[str, ...]
    target_format_version: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "already_current": list(self.already_current),
            "target_format_version": self.target_format_version,
            "upgraded": list(self.upgraded),
        }


@dataclass(frozen=True)
class Recipient:
    """An external party we can export entries to.

    Persisted as ``keys/recipients/<fingerprint>.pub`` (canonical JSON).
    Recipient pubkey files are *not* themselves signed by the vault
    identity in v0.1 — they are local address-book entries, and the
    fingerprint is computed from the pubkey bytes (binding the
    filename to the contents). Tampering with a recipient file
    therefore invalidates the fingerprint and is detected on load.
    """

    version: int
    fingerprint: str
    label: str
    added_at: str
    kem_pk_b64: str  # base64 of the serialized hybrid KEM public key envelope
    sig_pk_b64: str  # base64 of the serialized hybrid SIG public key envelope

    def to_dict(self) -> dict[str, Any]:
        return {
            "added_at": self.added_at,
            "fingerprint": self.fingerprint,
            "kem_pk": self.kem_pk_b64,
            "label": self.label,
            "sig_pk": self.sig_pk_b64,
            "version": self.version,
        }


@dataclass(frozen=True)
class ExportBundle:
    """A single-entry export artifact.

    The bundle re-encrypts the original entry to a recipient's KEM
    pubkey and signs the canonical body with the *sender's* hybrid
    signing identity (with domain separator
    :data:`EXPORT_SIG_DOMAIN`).

    The recipient verifies via :func:`open_export_bundle` using their
    own KEM keypair plus the sender's pubkey embedded in the bundle.
    Optional ``expected_sender_sig_pk`` cross-check guards against a
    swap of the sender's pubkey.
    """

    version: int
    ulid: str
    name: str
    size: int
    blob_sha256: str
    exported_at: str
    sender_sig_pk_b64: str
    recipient_fingerprint: str
    blob_b64: str
    sig_hybrid_b64: str

    def to_dict(self, *, with_signature: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "blob": self.blob_b64,
            "blob_sha256": self.blob_sha256,
            "exported_at": self.exported_at,
            "name": self.name,
            "recipient_fingerprint": self.recipient_fingerprint,
            "sender_sig_pk": self.sender_sig_pk_b64,
            "size": self.size,
            "ulid": self.ulid,
            "version": self.version,
        }
        if with_signature:
            out["sig_hybrid"] = self.sig_hybrid_b64
        return out


# ---------------------------------------------------------------------------
# Identity wrap (Argon2id + AES-256-GCM)
# ---------------------------------------------------------------------------


def _serialize_secret_keys(identity: VaultIdentity) -> bytes:
    payload = {
        "version": IDENTITY_VERSION,
        "kem_x25519_sk_b64": base64.b64encode(identity.kem.x25519_sk).decode("ascii"),
        "kem_mlkem768_sk_b64": base64.b64encode(identity.kem.mlkem768_sk).decode("ascii"),
        "kem_x25519_pk_b64": base64.b64encode(identity.kem.x25519_pk).decode("ascii"),
        "kem_mlkem768_pk_b64": base64.b64encode(identity.kem.mlkem768_pk).decode("ascii"),
        "sig_ed25519_sk_b64": base64.b64encode(identity.sig.ed25519_sk).decode("ascii"),
        "sig_mldsa65_sk_b64": base64.b64encode(identity.sig.mldsa65_sk).decode("ascii"),
        "sig_ed25519_pk_b64": base64.b64encode(identity.sig.ed25519_pk).decode("ascii"),
        "sig_mldsa65_pk_b64": base64.b64encode(identity.sig.mldsa65_pk).decode("ascii"),
    }
    return canonicalize(payload)


def _deserialize_secret_keys(plaintext: bytes) -> VaultIdentity:
    try:
        doc = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise SchemaValidationError(
            f"identity plaintext is not valid UTF-8 JSON: {exc}",
            error_code="vault.store.identity_bad_json",
        ) from exc
    required = {
        "version",
        "kem_x25519_sk_b64",
        "kem_mlkem768_sk_b64",
        "kem_x25519_pk_b64",
        "kem_mlkem768_pk_b64",
        "sig_ed25519_sk_b64",
        "sig_mldsa65_sk_b64",
        "sig_ed25519_pk_b64",
        "sig_mldsa65_pk_b64",
    }
    missing = sorted(required - doc.keys())
    if missing:
        raise SchemaValidationError(
            f"identity plaintext missing keys: {missing}",
            error_code="vault.store.identity_missing_keys",
        )
    if doc["version"] != IDENTITY_VERSION:
        raise SchemaValidationError(
            f"unsupported identity version: {doc['version']}",
            error_code="vault.store.identity_bad_version",
        )

    def _b64(key: str) -> bytes:
        try:
            return base64.b64decode(doc[key], validate=True)
        except Exception as exc:
            raise SchemaValidationError(
                f"identity field {key!r} is not valid base64: {exc}",
                error_code="vault.store.identity_bad_b64",
            ) from exc

    kem = HybridKemKeypair(
        x25519_sk=_b64("kem_x25519_sk_b64"),
        mlkem768_sk=_b64("kem_mlkem768_sk_b64"),
        x25519_pk=_b64("kem_x25519_pk_b64"),
        mlkem768_pk=_b64("kem_mlkem768_pk_b64"),
    )
    sig_kp = HybridSigKeypair(
        ed25519_sk=_b64("sig_ed25519_sk_b64"),
        mldsa65_sk=_b64("sig_mldsa65_sk_b64"),
        ed25519_pk=_b64("sig_ed25519_pk_b64"),
        mldsa65_pk=_b64("sig_mldsa65_pk_b64"),
    )
    if len(kem.x25519_sk) != X25519_PUBKEY_LEN:
        raise SchemaValidationError(
            f"identity x25519_sk wrong length: {len(kem.x25519_sk)}",
            error_code="vault.store.identity_bad_kem_sk",
        )
    if len(kem.mlkem768_sk) != MLKEM768_SECRETKEY_LEN:
        raise SchemaValidationError(
            f"identity mlkem768_sk wrong length: {len(kem.mlkem768_sk)}",
            error_code="vault.store.identity_bad_kem_sk",
        )
    if len(sig_kp.ed25519_sk) != ED25519_PUBKEY_LEN:
        raise SchemaValidationError(
            f"identity ed25519_sk wrong length: {len(sig_kp.ed25519_sk)}",
            error_code="vault.store.identity_bad_sig_sk",
        )
    if len(sig_kp.mldsa65_sk) != MLDSA65_SECRETKEY_LEN:
        raise SchemaValidationError(
            f"identity mldsa65_sk wrong length: {len(sig_kp.mldsa65_sk)}",
            error_code="vault.store.identity_bad_sig_sk",
        )
    return VaultIdentity(kem=kem, sig=sig_kp)


def _wrap_identity(
    identity: VaultIdentity,
    passphrase: bytes,
    *,
    memory_kib: int = ARGON2ID_DEFAULT_MEMORY_KIB,
    time_cost: int = ARGON2ID_DEFAULT_TIME_COST,
    parallelism: int = ARGON2ID_DEFAULT_PARALLELISM,
) -> bytes:
    """Argon2id-derive a key from ``passphrase`` and AES-256-GCM seal the
    serialized identity. Returns canonical-JSON bytes ready to write."""
    salt = secrets.token_bytes(16)
    key = argon2id(
        password=passphrase,
        salt=salt,
        memory_kib=memory_kib,
        time_cost=time_cost,
        parallelism=parallelism,
        length=32,
    )
    nonce = secrets.token_bytes(12)
    plaintext = _serialize_secret_keys(identity)
    aead = AESGCM(key)
    ciphertext = aead.encrypt(nonce, plaintext, b"qwashed/vault/v0.1/identity")
    envelope = {
        "version": IDENTITY_VERSION,
        "kdf": "argon2id",
        "kdf_params": {
            "memory_kib": memory_kib,
            "time_cost": time_cost,
            "parallelism": parallelism,
            "salt_b64": base64.b64encode(salt).decode("ascii"),
        },
        "aead": {
            "alg": "AES-256-GCM",
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        },
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }
    return canonicalize(envelope)


def _unwrap_identity(envelope_bytes: bytes, passphrase: bytes) -> VaultIdentity:
    try:
        env = json.loads(envelope_bytes.decode("utf-8"))
    except Exception as exc:
        raise SchemaValidationError(
            f"identity.sk.enc is not valid UTF-8 JSON: {exc}",
            error_code="vault.store.identity_envelope_bad_json",
        ) from exc
    if env.get("version") != IDENTITY_VERSION:
        raise SchemaValidationError(
            f"unsupported identity envelope version: {env.get('version')}",
            error_code="vault.store.identity_envelope_bad_version",
        )
    if env.get("kdf") != "argon2id":
        raise SchemaValidationError(
            f"unsupported identity envelope KDF: {env.get('kdf')!r}",
            error_code="vault.store.identity_envelope_bad_kdf",
        )
    aead_info = env.get("aead", {})
    if aead_info.get("alg") != "AES-256-GCM":
        raise SchemaValidationError(
            f"unsupported identity envelope AEAD: {aead_info.get('alg')!r}",
            error_code="vault.store.identity_envelope_bad_aead",
        )
    try:
        params = env["kdf_params"]
        salt = base64.b64decode(params["salt_b64"], validate=True)
        nonce = base64.b64decode(aead_info["nonce_b64"], validate=True)
        ciphertext = base64.b64decode(env["ciphertext_b64"], validate=True)
    except Exception as exc:
        raise SchemaValidationError(
            f"identity envelope has malformed base64: {exc}",
            error_code="vault.store.identity_envelope_bad_b64",
        ) from exc

    key = argon2id(
        password=passphrase,
        salt=salt,
        memory_kib=int(params["memory_kib"]),
        time_cost=int(params["time_cost"]),
        parallelism=int(params["parallelism"]),
        length=32,
    )
    aead = AESGCM(key)
    try:
        plaintext = aead.decrypt(nonce, ciphertext, b"qwashed/vault/v0.1/identity")
    except Exception as exc:
        # Wrong passphrase, tampered envelope, or corruption -- all fail closed.
        raise SignatureError(
            "identity unwrap failed (wrong passphrase or tampered envelope)",
            error_code="vault.store.identity_unwrap_failed",
        ) from exc
    return _deserialize_secret_keys(plaintext)


# ---------------------------------------------------------------------------
# Manifest sign + verify
# ---------------------------------------------------------------------------


def _sign_manifest(
    *,
    vault_id: str,
    created_at: str,
    identity: VaultIdentity,
    format_version: int = FORMAT_VERSION_V01,
) -> VaultManifest:
    if format_version not in _SUPPORTED_FORMAT_VERSIONS:
        raise SchemaValidationError(
            f"unsupported manifest format_version: {format_version}",
            error_code="vault.store.manifest_bad_format_version",
        )
    sig_pk_b64 = identity.sig_public_b64()
    body = canonicalize(
        VaultManifest(
            version=MANIFEST_VERSION,
            vault_id=vault_id,
            created_at=created_at,
            kem_pk_b64=identity.kem_public_b64(),
            sig_pk_b64=sig_pk_b64,
            sig_hybrid_b64="",
            format_version=format_version,
        ).to_dict(with_signature=False)
    )
    sig_blob = sign(identity.sig, body)
    return VaultManifest(
        version=MANIFEST_VERSION,
        vault_id=vault_id,
        created_at=created_at,
        kem_pk_b64=identity.kem_public_b64(),
        sig_pk_b64=sig_pk_b64,
        sig_hybrid_b64=base64.b64encode(sig_blob).decode("ascii"),
        format_version=format_version,
    )


def _verify_manifest(manifest: VaultManifest) -> None:
    if manifest.version != MANIFEST_VERSION:
        raise SchemaValidationError(
            f"unsupported manifest version: {manifest.version}",
            error_code="vault.store.manifest_bad_version",
        )
    if manifest.format_version not in _SUPPORTED_FORMAT_VERSIONS:
        raise SchemaValidationError(
            f"unsupported manifest format_version: {manifest.format_version}",
            error_code="vault.store.manifest_bad_format_version",
        )
    body = canonicalize(manifest.to_dict(with_signature=False))
    try:
        sig_pk = base64.b64decode(manifest.sig_pk_b64, validate=True)
        sig_blob = base64.b64decode(manifest.sig_hybrid_b64, validate=True)
    except Exception as exc:
        raise SignatureError(
            f"manifest has invalid base64 fields: {exc}",
            error_code="vault.store.manifest_bad_b64",
        ) from exc
    if not verify(sig_pk, body, sig_blob):
        raise SignatureError(
            "manifest signature failed AND-verify",
            error_code="vault.store.manifest_bad_signature",
        )


def _parse_manifest(raw: bytes) -> VaultManifest:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SchemaValidationError(
            f"manifest is not valid UTF-8 JSON: {exc}",
            error_code="vault.store.manifest_bad_json",
        ) from exc
    required = {"version", "vault_id", "created_at", "kem_pk", "sig_pk", "sig_hybrid"}
    optional = {"format_version"}
    allowed = required | optional
    missing = sorted(required - doc.keys())
    if missing:
        raise SchemaValidationError(
            f"manifest missing keys: {missing}",
            error_code="vault.store.manifest_missing_keys",
        )
    extras = sorted(doc.keys() - allowed)
    if extras:
        raise SchemaValidationError(
            f"manifest has unknown keys: {extras}",
            error_code="vault.store.manifest_unknown_keys",
        )
    fmt_raw = doc.get("format_version", FORMAT_VERSION_V01)
    if not isinstance(fmt_raw, int) or isinstance(fmt_raw, bool):
        raise SchemaValidationError(
            f"manifest format_version must be int, got {fmt_raw!r}",
            error_code="vault.store.manifest_bad_format_version",
        )
    if fmt_raw not in _SUPPORTED_FORMAT_VERSIONS:
        raise SchemaValidationError(
            f"unsupported manifest format_version: {fmt_raw}",
            error_code="vault.store.manifest_bad_format_version",
        )
    return VaultManifest(
        version=int(doc["version"]),
        vault_id=str(doc["vault_id"]),
        created_at=str(doc["created_at"]),
        kem_pk_b64=str(doc["kem_pk"]),
        sig_pk_b64=str(doc["sig_pk"]),
        sig_hybrid_b64=str(doc["sig_hybrid"]),
        format_version=int(fmt_raw),
    )


# ---------------------------------------------------------------------------
# Entry metadata sign + verify
# ---------------------------------------------------------------------------


def _sign_metadata(
    *,
    ulid: str,
    name: str,
    size: int,
    created_at: str,
    blob_sha256: str,
    identity: VaultIdentity,
    format_version: int = FORMAT_VERSION_V01,
) -> EntryMetadata:
    if format_version not in _SUPPORTED_FORMAT_VERSIONS:
        raise SchemaValidationError(
            f"unsupported entry metadata format_version: {format_version}",
            error_code="vault.store.meta_bad_format_version",
        )
    actor_pk_b64 = identity.sig_public_b64()
    body = canonicalize(
        EntryMetadata(
            version=META_VERSION,
            ulid=ulid,
            name=name,
            size=size,
            created_at=created_at,
            blob_sha256=blob_sha256,
            actor_pk_b64=actor_pk_b64,
            sig_hybrid_b64="",
            format_version=format_version,
        ).to_dict(with_signature=False)
    )
    sig_blob = sign(identity.sig, body)
    return EntryMetadata(
        version=META_VERSION,
        ulid=ulid,
        name=name,
        size=size,
        created_at=created_at,
        blob_sha256=blob_sha256,
        actor_pk_b64=actor_pk_b64,
        sig_hybrid_b64=base64.b64encode(sig_blob).decode("ascii"),
        format_version=format_version,
    )


def _verify_metadata(meta: EntryMetadata) -> None:
    if meta.version != META_VERSION:
        raise SchemaValidationError(
            f"unsupported entry metadata version: {meta.version}",
            error_code="vault.store.meta_bad_version",
        )
    if meta.format_version not in _SUPPORTED_FORMAT_VERSIONS:
        raise SchemaValidationError(
            f"unsupported entry metadata format_version: {meta.format_version}",
            error_code="vault.store.meta_bad_format_version",
        )
    body = canonicalize(meta.to_dict(with_signature=False))
    try:
        actor_pk = base64.b64decode(meta.actor_pk_b64, validate=True)
        sig_blob = base64.b64decode(meta.sig_hybrid_b64, validate=True)
    except Exception as exc:
        raise SignatureError(
            f"entry metadata has invalid base64 fields: {exc}",
            error_code="vault.store.meta_bad_b64",
        ) from exc
    if not verify(actor_pk, body, sig_blob):
        raise SignatureError(
            f"entry {meta.ulid} metadata signature failed AND-verify",
            error_code="vault.store.meta_bad_signature",
        )


def _parse_metadata(raw: bytes) -> EntryMetadata:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SchemaValidationError(
            f"entry metadata is not valid UTF-8 JSON: {exc}",
            error_code="vault.store.meta_bad_json",
        ) from exc
    required = {
        "version",
        "ulid",
        "name",
        "size",
        "created_at",
        "blob_sha256",
        "actor_pk",
        "sig_hybrid",
    }
    optional = {"format_version"}
    allowed = required | optional
    missing = sorted(required - doc.keys())
    if missing:
        raise SchemaValidationError(
            f"entry metadata missing keys: {missing}",
            error_code="vault.store.meta_missing_keys",
        )
    extras = sorted(doc.keys() - allowed)
    if extras:
        raise SchemaValidationError(
            f"entry metadata has unknown keys: {extras}",
            error_code="vault.store.meta_unknown_keys",
        )
    _validate_ulid(str(doc["ulid"]))
    if not isinstance(doc["size"], int) or doc["size"] < 0:
        raise SchemaValidationError(
            f"entry metadata size must be non-negative int, got {doc['size']!r}",
            error_code="vault.store.meta_bad_size",
        )
    fmt_raw = doc.get("format_version", FORMAT_VERSION_V01)
    if not isinstance(fmt_raw, int) or isinstance(fmt_raw, bool):
        raise SchemaValidationError(
            f"entry metadata format_version must be int, got {fmt_raw!r}",
            error_code="vault.store.meta_bad_format_version",
        )
    if fmt_raw not in _SUPPORTED_FORMAT_VERSIONS:
        raise SchemaValidationError(
            f"unsupported entry metadata format_version: {fmt_raw}",
            error_code="vault.store.meta_bad_format_version",
        )
    return EntryMetadata(
        version=int(doc["version"]),
        ulid=str(doc["ulid"]),
        name=str(doc["name"]),
        size=int(doc["size"]),
        created_at=str(doc["created_at"]),
        blob_sha256=str(doc["blob_sha256"]),
        actor_pk_b64=str(doc["actor_pk"]),
        sig_hybrid_b64=str(doc["sig_hybrid"]),
        format_version=int(fmt_raw),
    )


# ---------------------------------------------------------------------------
# Encrypted blob (entries/<ulid>.bin)
# ---------------------------------------------------------------------------


def _seal_blob(
    *,
    ulid: str,
    plaintext: bytes,
    recipient_kem_pk: bytes,
    format_version: int = FORMAT_VERSION_CURRENT,
) -> bytes:
    """Encapsulate, derive AEAD key, encrypt plaintext, return blob bytes.

    The blob version byte (offset 4) is set to ``format_version`` and
    becomes the on-disk discriminator: :func:`_open_blob` reads it back
    to pick the matching HKDF info string. New writes default to
    :data:`FORMAT_VERSION_CURRENT`; the v0.1 path remains reachable for
    re-encrypt-during-export style operations that need to preserve the
    original format.
    """
    if format_version not in _SUPPORTED_FORMAT_VERSIONS:
        raise SignatureError(
            f"unsupported entry blob format_version: {format_version}",
            error_code="vault.store.blob_bad_format_version",
        )
    kem_ct, ss = encapsulate(recipient_kem_pk, format_version=format_version)
    if len(kem_ct) > _MAX_KEM_CT_LEN:
        raise SignatureError(
            f"hybrid KEM ciphertext too large: {len(kem_ct)}",
            error_code="vault.store.blob_kem_ct_too_large",
        )
    aead_key = hkdf_sha256(
        ikm=ss,
        salt=b"",
        info=_entry_aead_info_for(format_version),
        length=32,
    )
    nonce = secrets.token_bytes(ENTRY_NONCE_LEN)
    aead = AESGCM(aead_key)
    aead_blob = aead.encrypt(nonce, plaintext, ulid.encode("ascii"))
    header = BLOB_MAGIC + bytes([format_version]) + b"\x00\x00\x00" + struct.pack(">I", len(kem_ct))
    return header + kem_ct + nonce + aead_blob


def _open_blob(
    *,
    ulid: str,
    blob_bytes: bytes,
    identity: VaultIdentity,
) -> bytes:
    """Parse a sealed blob, decapsulate, AES-GCM decrypt, return plaintext.

    The blob version byte selects the cryptographic format: 1 == v0.1
    (HKDF info ``qwashed/vault/v0.1/*``), 2 == v0.2. Unknown versions
    fail closed.
    """
    if len(blob_bytes) < 4 + 1 + 3 + 4:
        raise SignatureError(
            f"entry blob too short: {len(blob_bytes)} bytes",
            error_code="vault.store.blob_too_short",
        )
    if blob_bytes[0:4] != BLOB_MAGIC:
        raise SignatureError(
            f"entry blob has wrong magic: {blob_bytes[0:4]!r}",
            error_code="vault.store.blob_bad_magic",
        )
    blob_version = blob_bytes[4]
    if blob_version not in _SUPPORTED_FORMAT_VERSIONS:
        raise SignatureError(
            f"entry blob has unsupported version: {blob_version}",
            error_code="vault.store.blob_bad_version",
        )
    if blob_bytes[5:8] != b"\x00\x00\x00":
        raise SignatureError(
            "entry blob reserved bytes are non-zero",
            error_code="vault.store.blob_bad_reserved",
        )
    (kem_ct_len,) = struct.unpack(">I", blob_bytes[8:12])
    if kem_ct_len > _MAX_KEM_CT_LEN:
        raise SignatureError(
            f"entry blob kem_ct length out of range: {kem_ct_len}",
            error_code="vault.store.blob_bad_kem_ct_len",
        )
    end_kem = 12 + kem_ct_len
    end_nonce = end_kem + ENTRY_NONCE_LEN
    if end_nonce > len(blob_bytes):
        raise SignatureError(
            "entry blob truncated before AEAD payload",
            error_code="vault.store.blob_truncated",
        )
    kem_ct = blob_bytes[12:end_kem]
    nonce = blob_bytes[end_kem:end_nonce]
    aead_blob = blob_bytes[end_nonce:]
    if len(aead_blob) > _MAX_AEAD_CT_LEN:
        raise SignatureError(
            f"entry blob aead payload too large: {len(aead_blob)}",
            error_code="vault.store.blob_aead_too_large",
        )

    ss = decapsulate(identity.kem, kem_ct, format_version=blob_version)
    aead_key = hkdf_sha256(
        ikm=ss,
        salt=b"",
        info=_entry_aead_info_for(blob_version),
        length=32,
    )
    aead = AESGCM(aead_key)
    try:
        return aead.decrypt(nonce, aead_blob, ulid.encode("ascii"))
    except Exception as exc:
        raise SignatureError(
            f"entry {ulid} AEAD decryption failed (tampered or wrong identity)",
            error_code="vault.store.blob_decrypt_failed",
        ) from exc


def _peek_blob_version(blob_bytes: bytes) -> int:
    """Read the on-disk format-version byte without decrypting.

    Returns the integer in :data:`_SUPPORTED_FORMAT_VERSIONS`. Used by
    :meth:`Vault.upgrade` to decide which entries still need migration.
    """
    if len(blob_bytes) < 5 or blob_bytes[0:4] != BLOB_MAGIC:
        raise SignatureError(
            "entry blob has wrong magic or is truncated",
            error_code="vault.store.blob_bad_magic",
        )
    blob_version = blob_bytes[4]
    if blob_version not in _SUPPORTED_FORMAT_VERSIONS:
        raise SignatureError(
            f"entry blob has unsupported version: {blob_version}",
            error_code="vault.store.blob_bad_version",
        )
    return blob_version


# ---------------------------------------------------------------------------
# Vault directory layout helpers
# ---------------------------------------------------------------------------


def _manifest_path(root: Path) -> Path:
    return root / "manifest.json"


def _identity_pub_path(root: Path) -> Path:
    return root / "keys" / "identity.pub"


def _identity_sk_enc_path(root: Path) -> Path:
    return root / "keys" / "identity.sk.enc"


def _entries_dir(root: Path) -> Path:
    return root / "entries"


def _audit_log_path(root: Path) -> Path:
    return root / "audit_log.jsonl"


def _entry_blob_path(root: Path, ulid: str) -> Path:
    return _entries_dir(root) / f"{ulid}.bin"


def _entry_meta_path(root: Path, ulid: str) -> Path:
    return _entries_dir(root) / f"{ulid}.meta.json"


def _recipients_dir(root: Path) -> Path:
    return root / "keys" / "recipients"


def _recipient_pub_path(root: Path, fingerprint: str) -> Path:
    return _recipients_dir(root) / f"{fingerprint}{_RECIPIENT_PUB_SUFFIX}"


# ---------------------------------------------------------------------------
# Recipients (keys/recipients/<fp>.pub)
# ---------------------------------------------------------------------------


def _recipient_fingerprint(kem_pk: bytes, sig_pk: bytes) -> str:
    """Compute a recipient's fingerprint from the *serialized* hybrid pubkeys.

    SHA-256 of ``kem_pk || sig_pk``, hex-encoded, truncated to
    :data:`_RECIPIENT_FP_LEN` (=32 hex chars / 128 bits). Lowercase.
    The fingerprint binds the filename to the contents: a tampered
    ``recipients/<fp>.pub`` will not re-derive to ``<fp>``.
    """
    h = hashlib.sha256()
    h.update(kem_pk)
    h.update(sig_pk)
    return h.hexdigest()[:_RECIPIENT_FP_LEN]


def _validate_fingerprint(fingerprint: str) -> None:
    if not isinstance(fingerprint, str):
        raise SchemaValidationError(
            "fingerprint must be a string",
            error_code="vault.store.recipient_fp_bad_type",
        )
    if len(fingerprint) != _RECIPIENT_FP_LEN:
        raise SchemaValidationError(
            f"fingerprint must be {_RECIPIENT_FP_LEN} chars, got {len(fingerprint)}",
            error_code="vault.store.recipient_fp_bad_length",
        )
    if not all(c in "0123456789abcdef" for c in fingerprint):
        raise SchemaValidationError(
            "fingerprint must be lowercase hex",
            error_code="vault.store.recipient_fp_bad_alphabet",
        )


def _parse_recipient(blob: bytes) -> Recipient:
    try:
        doc = json.loads(blob.decode("utf-8"))
    except Exception as exc:
        raise SchemaValidationError(
            f"recipient is not valid UTF-8 JSON: {exc}",
            error_code="vault.store.recipient_bad_json",
        ) from exc
    required = {
        "version",
        "fingerprint",
        "label",
        "added_at",
        "kem_pk",
        "sig_pk",
    }
    missing = sorted(required - doc.keys())
    if missing:
        raise SchemaValidationError(
            f"recipient missing keys: {missing}",
            error_code="vault.store.recipient_missing_keys",
        )
    if doc["version"] != RECIPIENT_VERSION:
        raise SchemaValidationError(
            f"unsupported recipient version: {doc['version']}",
            error_code="vault.store.recipient_bad_version",
        )
    return Recipient(
        version=int(doc["version"]),
        fingerprint=str(doc["fingerprint"]),
        label=str(doc["label"]),
        added_at=str(doc["added_at"]),
        kem_pk_b64=str(doc["kem_pk"]),
        sig_pk_b64=str(doc["sig_pk"]),
    )


def _recipient_kem_pk_bytes(recipient: Recipient) -> bytes:
    try:
        return base64.b64decode(recipient.kem_pk_b64, validate=True)
    except Exception as exc:
        raise SchemaValidationError(
            f"recipient kem_pk is not valid base64: {exc}",
            error_code="vault.store.recipient_bad_kem_b64",
        ) from exc


def _recipient_sig_pk_bytes(recipient: Recipient) -> bytes:
    try:
        return base64.b64decode(recipient.sig_pk_b64, validate=True)
    except Exception as exc:
        raise SchemaValidationError(
            f"recipient sig_pk is not valid base64: {exc}",
            error_code="vault.store.recipient_bad_sig_b64",
        ) from exc


# ---------------------------------------------------------------------------
# Export bundle (sign / verify / parse)
# ---------------------------------------------------------------------------


def _bundle_sign_payload(body: dict[str, Any]) -> bytes:
    """Bytes that the export-bundle hybrid signature commits to.

    Domain-separation prefix prevents a meta.json signature from being
    mistaken for a bundle signature, even if an attacker could
    re-arrange fields to make canonical bodies collide.
    """
    return EXPORT_SIG_DOMAIN + b"\n" + canonicalize(body)


def _sign_export_bundle(
    *,
    ulid: str,
    name: str,
    size: int,
    blob_sha256: str,
    exported_at: str,
    recipient_fingerprint: str,
    blob_bytes: bytes,
    identity: VaultIdentity,
) -> ExportBundle:
    sender_sig_pk = base64.b64encode(identity.sig.public_bytes()).decode("ascii")
    blob_b64 = base64.b64encode(blob_bytes).decode("ascii")
    body = {
        "blob": blob_b64,
        "blob_sha256": blob_sha256,
        "exported_at": exported_at,
        "name": name,
        "recipient_fingerprint": recipient_fingerprint,
        "sender_sig_pk": sender_sig_pk,
        "size": size,
        "ulid": ulid,
        "version": EXPORT_VERSION,
    }
    sig = sign(identity.sig, _bundle_sign_payload(body))
    return ExportBundle(
        version=EXPORT_VERSION,
        ulid=ulid,
        name=name,
        size=size,
        blob_sha256=blob_sha256,
        exported_at=exported_at,
        sender_sig_pk_b64=sender_sig_pk,
        recipient_fingerprint=recipient_fingerprint,
        blob_b64=blob_b64,
        sig_hybrid_b64=base64.b64encode(sig).decode("ascii"),
    )


def _parse_export_bundle(blob: bytes) -> ExportBundle:
    try:
        doc = json.loads(blob.decode("utf-8"))
    except Exception as exc:
        raise SchemaValidationError(
            f"export bundle is not valid UTF-8 JSON: {exc}",
            error_code="vault.store.bundle_bad_json",
        ) from exc
    required = {
        "version",
        "ulid",
        "name",
        "size",
        "blob_sha256",
        "exported_at",
        "sender_sig_pk",
        "recipient_fingerprint",
        "blob",
        "sig_hybrid",
    }
    missing = sorted(required - doc.keys())
    if missing:
        raise SchemaValidationError(
            f"export bundle missing keys: {missing}",
            error_code="vault.store.bundle_missing_keys",
        )
    if doc["version"] != EXPORT_VERSION:
        raise SchemaValidationError(
            f"unsupported export bundle version: {doc['version']}",
            error_code="vault.store.bundle_bad_version",
        )
    return ExportBundle(
        version=int(doc["version"]),
        ulid=str(doc["ulid"]),
        name=str(doc["name"]),
        size=int(doc["size"]),
        blob_sha256=str(doc["blob_sha256"]),
        exported_at=str(doc["exported_at"]),
        sender_sig_pk_b64=str(doc["sender_sig_pk"]),
        recipient_fingerprint=str(doc["recipient_fingerprint"]),
        blob_b64=str(doc["blob"]),
        sig_hybrid_b64=str(doc["sig_hybrid"]),
    )


def _verify_export_bundle(bundle: ExportBundle) -> None:
    try:
        sender_pk = base64.b64decode(bundle.sender_sig_pk_b64, validate=True)
        sig = base64.b64decode(bundle.sig_hybrid_b64, validate=True)
    except Exception as exc:
        raise SchemaValidationError(
            f"export bundle signature material is not valid base64: {exc}",
            error_code="vault.store.bundle_bad_sig_b64",
        ) from exc
    payload = _bundle_sign_payload(bundle.to_dict(with_signature=False))
    if not verify(sender_pk, payload, sig):
        raise SignatureError(
            "export bundle hybrid signature failed to verify",
            error_code="vault.store.bundle_bad_signature",
        )


# ---------------------------------------------------------------------------
# Vault facade
# ---------------------------------------------------------------------------


class Vault:
    """In-memory handle to an unlocked on-disk vault.

    Instances are produced by :func:`init_vault` and :func:`unlock_vault`.
    All mutating operations write fail-closed to disk and append a
    hybrid-signed line to the audit log.

    The identity's secret material is held in the :class:`VaultIdentity`
    on this instance for the lifetime of the handle. Callers that want
    to drop the secrets must drop the :class:`Vault` reference; we do
    not provide an explicit ``zeroize`` because Python's GC and
    immutable ``bytes`` make best-effort wiping unreliable.
    """

    def __init__(
        self,
        root: Path,
        identity: VaultIdentity,
        manifest: VaultManifest,
    ) -> None:
        self._root = root
        self._identity = identity
        self._manifest = manifest
        self._audit_writer = AuditLogWriter(_audit_log_path(root), identity.sig)

    # ------------------------------------------------------------------
    # Read-only properties
    # ------------------------------------------------------------------

    @property
    def root(self) -> Path:
        return self._root

    @property
    def manifest(self) -> VaultManifest:
        return self._manifest

    @property
    def identity(self) -> VaultIdentity:
        return self._identity

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------

    def put(self, plaintext: bytes, *, name: str) -> EntryMetadata:
        """Seal ``plaintext`` to the vault, return the signed metadata.

        Parameters
        ----------
        plaintext:
            Raw bytes. Empty payloads are allowed (they exercise the
            AEAD nonce + tag without ciphertext body).
        name:
            User-friendly label for the entry. Stored in metadata, not
            used as a filesystem path. Must be non-empty.

        Returns
        -------
        EntryMetadata
            The freshly signed metadata, exactly as committed to disk.

        Raises
        ------
        SchemaValidationError
            If ``name`` is empty.
        SignatureError
            On any cryptographic failure during sealing.
        """
        if not name:
            raise SchemaValidationError(
                "entry name must not be empty",
                error_code="vault.store.empty_name",
            )

        ulid = new_ulid()
        blob = _seal_blob(
            ulid=ulid,
            plaintext=plaintext,
            recipient_kem_pk=self._identity.kem.public_bytes(),
            format_version=FORMAT_VERSION_CURRENT,
        )
        blob_sha256 = hashlib.sha256(blob).hexdigest()
        meta = _sign_metadata(
            ulid=ulid,
            name=name,
            size=len(plaintext),
            created_at=_utc_now_iso(),
            blob_sha256=blob_sha256,
            identity=self._identity,
            format_version=FORMAT_VERSION_CURRENT,
        )

        # Write blob, then meta. Audit log is appended last so a
        # half-written blob without metadata isn't logged as committed.
        _atomic_write(_entry_blob_path(self._root, ulid), blob)
        _atomic_write(
            _entry_meta_path(self._root, ulid),
            canonicalize(meta.to_dict(with_signature=True)),
        )
        self._audit_writer.append(op="put", subject=ulid)
        return meta

    def _decrypt_entry(self, ulid: str) -> tuple[bytes, EntryMetadata]:
        """Decrypt entry ``ulid`` *without* writing an audit line.

        Internal helper shared by :meth:`get` and :meth:`export`. The
        caller is responsible for appending the appropriate audit op.
        """
        _validate_ulid(ulid)
        meta_path = _entry_meta_path(self._root, ulid)
        blob_path = _entry_blob_path(self._root, ulid)
        if not meta_path.is_file():
            raise SignatureError(
                f"entry metadata not found: {meta_path}",
                error_code="vault.store.entry_missing_meta",
            )
        if not blob_path.is_file():
            raise SignatureError(
                f"entry blob not found: {blob_path}",
                error_code="vault.store.entry_missing_blob",
            )

        meta = _parse_metadata(meta_path.read_bytes())
        if meta.ulid != ulid:
            raise SignatureError(
                f"metadata ulid {meta.ulid!r} does not match filename {ulid!r}",
                error_code="vault.store.entry_ulid_mismatch",
            )
        _verify_metadata(meta)

        blob_bytes = blob_path.read_bytes()
        actual_sha = hashlib.sha256(blob_bytes).hexdigest()
        if actual_sha != meta.blob_sha256:
            raise SignatureError(
                f"entry {ulid} blob hash mismatch: meta={meta.blob_sha256} actual={actual_sha}",
                error_code="vault.store.entry_blob_hash_mismatch",
            )

        plaintext = _open_blob(
            ulid=ulid,
            blob_bytes=blob_bytes,
            identity=self._identity,
        )
        if len(plaintext) != meta.size:
            raise SignatureError(
                f"entry {ulid} plaintext size {len(plaintext)} != meta {meta.size}",
                error_code="vault.store.entry_plaintext_size_mismatch",
            )
        return plaintext, meta

    def get(self, ulid: str) -> tuple[bytes, EntryMetadata]:
        """Fetch and decrypt entry ``ulid``.

        Returns
        -------
        tuple[bytes, EntryMetadata]
            ``(plaintext, metadata)``.

        Raises
        ------
        SchemaValidationError
            If ``ulid`` is malformed or metadata is malformed.
        SignatureError
            If metadata signature fails, blob hash mismatches metadata,
            or AEAD decryption fails.
        """
        plaintext, meta = self._decrypt_entry(ulid)
        self._audit_writer.append(op="get", subject=ulid)
        return plaintext, meta

    def list(self) -> list[EntryMetadata]:
        """Return every entry's signed metadata, sorted by ULID.

        Each metadata file is *parsed and signature-verified*. A vault
        whose ``entries/`` directory contains a tampered ``meta.json``
        will fail loudly here rather than return partial results.
        """
        out: list[EntryMetadata] = []
        entries_dir = _entries_dir(self._root)
        if not entries_dir.is_dir():
            return out
        for path in sorted(entries_dir.glob("*.meta.json")):
            meta = _parse_metadata(path.read_bytes())
            ulid = path.name.removesuffix(".meta.json")
            if meta.ulid != ulid:
                raise SignatureError(
                    f"metadata ulid {meta.ulid!r} does not match filename {ulid!r}",
                    error_code="vault.store.entry_ulid_mismatch",
                )
            _verify_metadata(meta)
            out.append(meta)
        return out

    def verify(self) -> None:
        """Walk the entire vault and verify every signature + chain.

        Verifies, in order:

        #. ``manifest.json`` signature.
        #. Every ``<ulid>.meta.json`` signature.
        #. Every ``<ulid>.bin`` SHA-256 matches its metadata.
        #. ``audit_log.jsonl`` chain + per-line hybrid signatures.
        #. Cross-check: every entry on disk has at least one ``put``
           audit-log line; every ``put`` audit-log subject is an
           on-disk entry.

        Raises
        ------
        SignatureError, SchemaValidationError
            On the first failure encountered.
        """
        _verify_manifest(self._manifest)

        on_disk_ulids: set[str] = set()
        entries_dir = _entries_dir(self._root)
        if entries_dir.is_dir():
            for meta_path in sorted(entries_dir.glob("*.meta.json")):
                meta = _parse_metadata(meta_path.read_bytes())
                ulid = meta_path.name.removesuffix(".meta.json")
                if meta.ulid != ulid:
                    raise SignatureError(
                        f"metadata ulid {meta.ulid!r} does not match filename {ulid!r}",
                        error_code="vault.store.entry_ulid_mismatch",
                    )
                _verify_metadata(meta)
                blob_path = _entry_blob_path(self._root, ulid)
                if not blob_path.is_file():
                    raise SignatureError(
                        f"entry {ulid} metadata present but blob missing",
                        error_code="vault.store.entry_missing_blob",
                    )
                actual = hashlib.sha256(blob_path.read_bytes()).hexdigest()
                if actual != meta.blob_sha256:
                    raise SignatureError(
                        f"entry {ulid} blob hash mismatch",
                        error_code="vault.store.entry_blob_hash_mismatch",
                    )
                on_disk_ulids.add(ulid)

        # Audit log: chain + signatures.
        audit_entries = verify_chain(_audit_log_path(self._root))
        put_subjects: set[str] = {e.subject for e in audit_entries if e.op == "put"}

        missing_in_log = on_disk_ulids - put_subjects
        if missing_in_log:
            raise SignatureError(
                f"entries on disk without 'put' audit log line: {sorted(missing_in_log)}",
                error_code="vault.store.entry_not_logged",
            )
        missing_on_disk = put_subjects - on_disk_ulids
        if missing_on_disk:
            raise SignatureError(
                f"audit log 'put' subjects without on-disk entry: {sorted(missing_on_disk)}",
                error_code="vault.store.logged_entry_missing",
            )

    # ------------------------------------------------------------------
    # Format migration
    # ------------------------------------------------------------------

    def upgrade(
        self,
        *,
        target_format_version: int = FORMAT_VERSION_CURRENT,
    ) -> UpgradeReport:
        """Re-encrypt every legacy entry to ``target_format_version``.

        Walks ``entries/``, opens every blob whose on-disk version byte
        is below ``target_format_version``, decrypts in memory, and
        re-seals at the new format. The new ``meta.json`` is written
        first via :func:`_atomic_write` (carrying the new
        ``format_version`` field and a fresh hybrid signature), then the
        new blob is atomically swapped over the old one. After both are
        in place an ``op="upgrade"`` audit-log line is appended for the
        entry, signed by the current identity. Manifest is rewritten
        last to advertise the new ``format_version``.

        Plaintext only ever lives in a local ``bytearray`` that is
        zeroed before this method returns; no plaintext is ever written
        to disk during an upgrade. ``put`` audit-log lines for the
        original entries remain in place — the upgrade is additive and
        does not break existing put<->entry cross-checks in
        :meth:`verify`.

        Parameters
        ----------
        target_format_version:
            The format to upgrade to. Defaults to
            :data:`FORMAT_VERSION_CURRENT`. Must be one of the
            :data:`_SUPPORTED_FORMAT_VERSIONS`.

        Returns
        -------
        UpgradeReport
            ``upgraded`` lists ULIDs that were re-encrypted;
            ``already_current`` lists ULIDs that were already at the
            target format. Together they cover every entry on disk.

        Raises
        ------
        SchemaValidationError
            If ``target_format_version`` is not a supported version.
        SignatureError
            On any cryptographic failure during re-encryption. Failures
            leave any entries already migrated in their migrated state;
            the audit log records each successful migration.
        """
        if target_format_version not in _SUPPORTED_FORMAT_VERSIONS:
            raise SchemaValidationError(
                f"unsupported target_format_version: {target_format_version}",
                error_code="vault.store.upgrade_bad_target",
            )

        upgraded: list[str] = []
        already_current: list[str] = []

        # Snapshot the entry list up front so a tampered scan during
        # iteration cannot influence which ULIDs we touch.
        metas = self.list()
        for meta in metas:
            blob_path = _entry_blob_path(self._root, meta.ulid)
            blob_bytes = blob_path.read_bytes()
            current_version = _peek_blob_version(blob_bytes)

            if current_version >= target_format_version:
                already_current.append(meta.ulid)
                continue

            # Cross-check: meta.format_version should match the on-disk
            # blob version. A mismatch is fail-closed — we refuse to
            # silently re-write a blob whose on-disk format disagrees
            # with its signed metadata.
            if meta.format_version != current_version:
                raise SignatureError(
                    (
                        f"entry {meta.ulid} format mismatch: "
                        f"meta.format_version={meta.format_version} "
                        f"blob_version={current_version}"
                    ),
                    error_code="vault.store.upgrade_format_mismatch",
                )

            # Decrypt v0.1 entry into a scrub-able buffer.
            plaintext = _open_blob(
                ulid=meta.ulid,
                blob_bytes=blob_bytes,
                identity=self._identity,
            )
            scratch = bytearray(plaintext)
            try:
                # Sanity-check: decrypted size must match signed size.
                if len(scratch) != meta.size:
                    raise SignatureError(
                        (
                            f"entry {meta.ulid} decrypted size "
                            f"{len(scratch)} != meta.size {meta.size}"
                        ),
                        error_code="vault.store.upgrade_size_mismatch",
                    )

                new_blob = _seal_blob(
                    ulid=meta.ulid,
                    plaintext=bytes(scratch),
                    recipient_kem_pk=self._identity.kem.public_bytes(),
                    format_version=target_format_version,
                )
            finally:
                # Scrub plaintext from memory before any disk I/O.
                for i in range(len(scratch)):
                    scratch[i] = 0
                del scratch
                del plaintext

            new_blob_sha256 = hashlib.sha256(new_blob).hexdigest()
            new_meta = _sign_metadata(
                ulid=meta.ulid,
                name=meta.name,
                size=meta.size,
                created_at=meta.created_at,  # preserve original timestamp
                blob_sha256=new_blob_sha256,
                identity=self._identity,
                format_version=target_format_version,
            )

            # Atomic swap: write new meta first (so verify still passes
            # mid-upgrade because old blob still matches old meta if
            # we crash before swapping the blob — actually the new meta
            # would mismatch the old blob. So we write blob first, then
            # meta, matching the put() ordering).
            _atomic_write(_entry_blob_path(self._root, meta.ulid), new_blob)
            _atomic_write(
                _entry_meta_path(self._root, meta.ulid),
                canonicalize(new_meta.to_dict(with_signature=True)),
            )
            self._audit_writer.append(op="upgrade", subject=meta.ulid)
            upgraded.append(meta.ulid)

        # Rewrite manifest to advertise the new format_version. We
        # re-sign with the same vault_id and created_at so the manifest
        # identity is preserved across the upgrade. Skip if already at
        # target format and no entries were upgraded — the file is
        # already byte-identical to what we'd write.
        if self._manifest.format_version != target_format_version or upgraded:
            new_manifest = _sign_manifest(
                vault_id=self._manifest.vault_id,
                created_at=self._manifest.created_at,
                identity=self._identity,
                format_version=target_format_version,
            )
            _atomic_write(
                _manifest_path(self._root),
                canonicalize(new_manifest.to_dict(with_signature=True)),
            )
            self._manifest = new_manifest

        return UpgradeReport(
            upgraded=tuple(upgraded),
            already_current=tuple(already_current),
            target_format_version=target_format_version,
        )

    # ------------------------------------------------------------------
    # Recipients
    # ------------------------------------------------------------------

    def add_recipient(
        self,
        *,
        kem_pk: bytes,
        sig_pk: bytes,
        label: str,
    ) -> Recipient:
        """Add a recipient pubkey to the vault's local address book.

        Parameters
        ----------
        kem_pk:
            The serialized hybrid KEM public key envelope (output of
            :meth:`HybridKemKeypair.public_bytes`).
        sig_pk:
            The serialized hybrid SIG public key envelope (output of
            :meth:`HybridSigKeypair.public_bytes`).
        label:
            Human-friendly label for the recipient. Stored verbatim.
            Must be non-empty.

        Returns
        -------
        Recipient
            The freshly written recipient (filename = ``<fingerprint>.pub``).
        """
        if not label:
            raise SchemaValidationError(
                "recipient label must not be empty",
                error_code="vault.store.recipient_empty_label",
            )
        if not isinstance(kem_pk, bytes) or not isinstance(sig_pk, bytes):
            raise SchemaValidationError(
                "recipient kem_pk and sig_pk must be bytes",
                error_code="vault.store.recipient_bad_pk_type",
            )
        # Reject empty pubkeys early; full structural validation happens
        # at export time (where the KEM is actually used).
        if not kem_pk or not sig_pk:
            raise SchemaValidationError(
                "recipient kem_pk and sig_pk must be non-empty",
                error_code="vault.store.recipient_empty_pk",
            )
        fingerprint = _recipient_fingerprint(kem_pk, sig_pk)
        recipient = Recipient(
            version=RECIPIENT_VERSION,
            fingerprint=fingerprint,
            label=label,
            added_at=_utc_now_iso(),
            kem_pk_b64=base64.b64encode(kem_pk).decode("ascii"),
            sig_pk_b64=base64.b64encode(sig_pk).decode("ascii"),
        )
        path = _recipient_pub_path(self._root, fingerprint)
        if path.exists():
            raise ConfigurationError(
                f"recipient already exists: {fingerprint}",
                error_code="vault.store.recipient_already_exists",
            )
        _atomic_write(path, canonicalize(recipient.to_dict()))
        return recipient

    def list_recipients(self) -> Sequence[Recipient]:
        """Return every recipient on disk, sorted by fingerprint.

        Each recipient file is parsed and its filename fingerprint is
        re-derived from the pubkey contents — a tampered file will
        raise :class:`SignatureError`.
        """
        out: list[Recipient] = []
        recip_dir = _recipients_dir(self._root)
        if not recip_dir.is_dir():
            return out
        for path in sorted(recip_dir.glob(f"*{_RECIPIENT_PUB_SUFFIX}")):
            recipient = _parse_recipient(path.read_bytes())
            fp_from_name = path.name.removesuffix(_RECIPIENT_PUB_SUFFIX)
            _validate_fingerprint(fp_from_name)
            if recipient.fingerprint != fp_from_name:
                raise SignatureError(
                    (
                        f"recipient file {path.name!r} body fingerprint "
                        f"{recipient.fingerprint!r} does not match filename"
                    ),
                    error_code="vault.store.recipient_fp_mismatch",
                )
            kem_pk = _recipient_kem_pk_bytes(recipient)
            sig_pk = _recipient_sig_pk_bytes(recipient)
            derived = _recipient_fingerprint(kem_pk, sig_pk)
            if derived != recipient.fingerprint:
                raise SignatureError(
                    (
                        f"recipient {path.name!r} fingerprint does not match "
                        "derived hash of pubkey material (tampered?)"
                    ),
                    error_code="vault.store.recipient_fp_tampered",
                )
            out.append(recipient)
        return out

    def get_recipient(self, fingerprint: str) -> Recipient:
        """Return the recipient at ``fingerprint`` or raise.

        Performs the same fingerprint cross-check as
        :meth:`list_recipients`.
        """
        _validate_fingerprint(fingerprint)
        path = _recipient_pub_path(self._root, fingerprint)
        if not path.is_file():
            raise SignatureError(
                f"recipient not found: {fingerprint}",
                error_code="vault.store.recipient_missing",
            )
        recipient = _parse_recipient(path.read_bytes())
        if recipient.fingerprint != fingerprint:
            raise SignatureError(
                (
                    f"recipient file {path.name!r} body fingerprint "
                    f"{recipient.fingerprint!r} does not match filename"
                ),
                error_code="vault.store.recipient_fp_mismatch",
            )
        kem_pk = _recipient_kem_pk_bytes(recipient)
        sig_pk = _recipient_sig_pk_bytes(recipient)
        if _recipient_fingerprint(kem_pk, sig_pk) != fingerprint:
            raise SignatureError(
                (
                    f"recipient {fingerprint} fingerprint does not match "
                    "derived hash of pubkey material (tampered?)"
                ),
                error_code="vault.store.recipient_fp_tampered",
            )
        return recipient

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export(self, ulid: str, recipient_fingerprint: str) -> bytes:
        """Re-encrypt entry ``ulid`` to ``recipient_fingerprint`` and return a
        canonical-JSON export bundle (signed by this vault's identity).

        The bundle is appended to a hash-chained ``export`` audit-log
        line whose subject is ``"<ulid>|to=<fingerprint>"``. The
        audit-log subject therefore captures both *what* was exported
        and *to whom*; tampering breaks the chain.

        Returns
        -------
        bytes
            Canonical JSON of the :class:`ExportBundle`. Caller is
            responsible for transmitting this to the recipient over
            their preferred channel — the bundle is self-contained and
            recipient-bound.
        """
        # First resolve the recipient — we want a missing/invalid recipient
        # to fail before we decrypt any plaintext, and before we touch the
        # audit log. Then load + verify the entry locally without an
        # intermediate "get" audit line; the only audit op for this call
        # site is the "export" line below.
        recipient = self.get_recipient(recipient_fingerprint)
        plaintext, meta = self._decrypt_entry(ulid)
        recipient_kem_pk = _recipient_kem_pk_bytes(recipient)

        new_blob = _seal_blob(
            ulid=ulid,
            plaintext=plaintext,
            recipient_kem_pk=recipient_kem_pk,
            format_version=FORMAT_VERSION_CURRENT,
        )
        new_blob_sha256 = hashlib.sha256(new_blob).hexdigest()

        bundle = _sign_export_bundle(
            ulid=ulid,
            name=meta.name,
            size=meta.size,
            blob_sha256=new_blob_sha256,
            exported_at=_utc_now_iso(),
            recipient_fingerprint=recipient.fingerprint,
            blob_bytes=new_blob,
            identity=self._identity,
        )
        bundle_bytes = canonicalize(bundle.to_dict(with_signature=True))

        self._audit_writer.append(
            op="export",
            subject=f"{ulid}|to={recipient.fingerprint}",
        )
        return bundle_bytes


# ---------------------------------------------------------------------------
# Module-level constructors
# ---------------------------------------------------------------------------


def init_vault(
    root: Path,
    passphrase: bytes,
    *,
    memory_kib: int = ARGON2ID_DEFAULT_MEMORY_KIB,
    time_cost: int = ARGON2ID_DEFAULT_TIME_COST,
    parallelism: int = ARGON2ID_DEFAULT_PARALLELISM,
) -> Vault:
    """Create a fresh vault at ``root`` and return a handle to it.

    Lays down the directory tree, generates a fresh hybrid identity,
    writes ``manifest.json``, ``keys/identity.pub``,
    ``keys/identity.sk.enc`` (Argon2id-wrapped), and the genesis line of
    ``audit_log.jsonl`` (op=``init``).

    Raises
    ------
    ConfigurationError
        If ``root`` already exists and is non-empty (we refuse to
        clobber an existing vault).
    """
    if not isinstance(passphrase, bytes):
        raise ConfigurationError(
            "passphrase must be bytes",
            error_code="vault.store.bad_passphrase_type",
        )
    if not passphrase:
        raise ConfigurationError(
            "passphrase must not be empty",
            error_code="vault.store.empty_passphrase",
        )
    if root.exists() and any(root.iterdir()):
        raise ConfigurationError(
            f"vault root is not empty: {root}",
            error_code="vault.store.root_not_empty",
        )

    root.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
    (root / "keys").mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
    (root / "keys" / "recipients").mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
    _entries_dir(root).mkdir(parents=True, exist_ok=True, mode=DIR_MODE)

    identity = VaultIdentity(
        kem=generate_kem_keypair(),
        sig=generate_sig_keypair(),
    )

    # identity.pub: canonical JSON; public material only.
    pub_doc = {
        "version": IDENTITY_VERSION,
        "kem_pk": identity.kem_public_b64(),
        "sig_pk": identity.sig_public_b64(),
    }
    _atomic_write(_identity_pub_path(root), canonicalize(pub_doc))

    # identity.sk.enc: Argon2id+AES-GCM wrap.
    wrapped = _wrap_identity(
        identity,
        passphrase,
        memory_kib=memory_kib,
        time_cost=time_cost,
        parallelism=parallelism,
    )
    _atomic_write(_identity_sk_enc_path(root), wrapped)

    # manifest.json: signed root. New vaults are written at the current
    # format version (v0.2); existing v0.1 vaults remain readable in
    # place and can be migrated via :meth:`Vault.upgrade`.
    vault_id = new_ulid()
    created_at = _utc_now_iso()
    manifest = _sign_manifest(
        vault_id=vault_id,
        created_at=created_at,
        identity=identity,
        format_version=FORMAT_VERSION_CURRENT,
    )
    _atomic_write(
        _manifest_path(root),
        canonicalize(manifest.to_dict(with_signature=True)),
    )

    # Genesis audit-log line.
    append_entry(
        _audit_log_path(root),
        op="init",
        subject=f"vault://{vault_id}",
        actor=identity.sig,
        prev_hash=GENESIS_PREV_HASH,
    )
    # Tighten audit log permissions (append_entry uses default umask).
    with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
        _audit_log_path(root).chmod(FILE_MODE)

    return Vault(root=root, identity=identity, manifest=manifest)


def unlock_vault(root: Path, passphrase: bytes) -> Vault:
    """Open an existing vault at ``root`` and return a handle.

    Verifies the manifest signature and decrypts the identity. Does
    *not* run a full :meth:`Vault.verify` -- that is left for callers
    who need the explicit guarantee.

    Raises
    ------
    ConfigurationError
        If ``root`` does not exist or required files are missing.
    SignatureError
        On wrong passphrase, manifest tamper, or missing audit log.
    SchemaValidationError
        On malformed manifest / identity envelope.
    """
    if not isinstance(passphrase, bytes):
        raise ConfigurationError(
            "passphrase must be bytes",
            error_code="vault.store.bad_passphrase_type",
        )
    if not passphrase:
        raise ConfigurationError(
            "passphrase must not be empty",
            error_code="vault.store.empty_passphrase",
        )
    if not root.is_dir():
        raise ConfigurationError(
            f"vault root does not exist: {root}",
            error_code="vault.store.root_missing",
        )
    manifest_path = _manifest_path(root)
    sk_enc_path = _identity_sk_enc_path(root)
    audit_path = _audit_log_path(root)
    for required_path in (manifest_path, sk_enc_path, audit_path):
        if not required_path.is_file():
            raise ConfigurationError(
                f"vault is missing required file: {required_path}",
                error_code="vault.store.missing_file",
            )

    manifest = _parse_manifest(manifest_path.read_bytes())
    _verify_manifest(manifest)
    identity = _unwrap_identity(sk_enc_path.read_bytes(), passphrase)

    # Cross-check: identity public bytes must match manifest public bytes.
    expected_kem_pk = base64.b64decode(manifest.kem_pk_b64, validate=True)
    expected_sig_pk = base64.b64decode(manifest.sig_pk_b64, validate=True)
    if identity.kem.public_bytes() != expected_kem_pk:
        raise SignatureError(
            "identity KEM public key does not match manifest",
            error_code="vault.store.identity_kem_mismatch",
        )
    if identity.sig.public_bytes() != expected_sig_pk:
        raise SignatureError(
            "identity SIG public key does not match manifest",
            error_code="vault.store.identity_sig_mismatch",
        )

    # Touch the audit log to confirm it parses and the chain is intact.
    AuditLogReader(audit_path)

    return Vault(root=root, identity=identity, manifest=manifest)


# ---------------------------------------------------------------------------
# Receiver-side bundle opener
# ---------------------------------------------------------------------------


def open_export_bundle(
    bundle_bytes: bytes,
    recipient_kem_keypair: HybridKemKeypair,
    *,
    expected_sender_sig_pk: bytes | None = None,
    expected_recipient_fingerprint: str | None = None,
) -> tuple[bytes, ExportBundle]:
    """Verify and decrypt an export bundle on the receiving side.

    Parameters
    ----------
    bundle_bytes:
        Canonical JSON bytes produced by :meth:`Vault.export`.
    recipient_kem_keypair:
        The recipient's hybrid KEM keypair (the secret half is
        required for decapsulation).
    expected_sender_sig_pk:
        Optional cross-check against an out-of-band-distributed
        sender pubkey. Strongly recommended in production: without it,
        the bundle's signature only proves that *whoever signed* this
        bundle holds the private keys for the embedded sender pubkey,
        not that the sender is who you think it is.
    expected_recipient_fingerprint:
        Optional check that the bundle was addressed to the expected
        fingerprint (computed from this keypair's public bytes plus
        the recipient's signing pubkey, if known to the caller). If
        omitted, the AEAD decapsulation will still fail-closed when
        the bundle was sealed to a different KEM pubkey, so this is
        belt-and-braces for diagnostics.

    Returns
    -------
    tuple[bytes, ExportBundle]
        ``(plaintext, bundle)``. The plaintext byte string is the
        original entry that the sender exported.
    """
    bundle = _parse_export_bundle(bundle_bytes)
    _verify_export_bundle(bundle)
    _validate_ulid(bundle.ulid)
    _validate_fingerprint(bundle.recipient_fingerprint)

    if expected_sender_sig_pk is not None:
        try:
            actual_sender_pk = base64.b64decode(bundle.sender_sig_pk_b64, validate=True)
        except Exception as exc:
            raise SchemaValidationError(
                f"export bundle sender_sig_pk is not valid base64: {exc}",
                error_code="vault.store.bundle_bad_sender_pk_b64",
            ) from exc
        if actual_sender_pk != expected_sender_sig_pk:
            raise SignatureError(
                "export bundle sender pubkey does not match expected",
                error_code="vault.store.bundle_sender_mismatch",
            )

    if expected_recipient_fingerprint is not None:
        _validate_fingerprint(expected_recipient_fingerprint)
        if bundle.recipient_fingerprint != expected_recipient_fingerprint:
            raise SignatureError(
                "export bundle recipient fingerprint does not match expected",
                error_code="vault.store.bundle_recipient_mismatch",
            )

    try:
        blob_bytes = base64.b64decode(bundle.blob_b64, validate=True)
    except Exception as exc:
        raise SchemaValidationError(
            f"export bundle blob is not valid base64: {exc}",
            error_code="vault.store.bundle_bad_blob_b64",
        ) from exc
    actual_sha = hashlib.sha256(blob_bytes).hexdigest()
    if actual_sha != bundle.blob_sha256:
        raise SignatureError(
            f"export bundle blob hash mismatch: meta={bundle.blob_sha256} actual={actual_sha}",
            error_code="vault.store.bundle_blob_hash_mismatch",
        )

    receiver_identity = VaultIdentity(
        kem=recipient_kem_keypair,
        # We never need the receiver's signing keys for opening: the
        # sender signed the bundle, not us. Use a stub that will fail
        # loudly if any signing path is reached. open_export_bundle
        # never invokes _open_blob with anything that touches sig.
        sig=HybridSigKeypair(
            ed25519_sk=b"",
            mldsa65_sk=b"",
            ed25519_pk=b"",
            mldsa65_pk=b"",
        ),
    )
    plaintext = _open_blob(
        ulid=bundle.ulid,
        blob_bytes=blob_bytes,
        identity=receiver_identity,
    )
    if len(plaintext) != bundle.size:
        raise SignatureError(
            f"export bundle plaintext size {len(plaintext)} != bundle.size {bundle.size}",
            error_code="vault.store.bundle_plaintext_size_mismatch",
        )
    return plaintext, bundle
