# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Key-derivation primitives for Qwashed: HKDF-SHA256 and Argon2id.

Two KDFs:

* :func:`hkdf_sha256` -- HKDF (RFC 5869) with SHA-256. Used to derive AEAD
  keys from KEM shared secrets and similar high-entropy inputs.
* :func:`argon2id` -- Argon2id (RFC 9106). Used for passphrase-protected
  identity material. NOT a network-side primitive; runs locally on the
  user's machine when unsealing the vault.

Both are wrappers over vetted libraries (``cryptography`` for HKDF,
``argon2-cffi`` for Argon2id) so Qwashed itself rolls no crypto. Both raise
:class:`KeyDerivationError` on any error path; silent fallback is a bug.

Argon2id parameter policy
-------------------------
The vault's default parameters are 64 MiB memory, 3 iterations, 1 lane.
This is the OWASP "modern device" baseline as of 2024. The minimums
:data:`ARGON2ID_MIN_MEMORY_KIB` / :data:`ARGON2ID_MIN_TIME_COST` are
fail-closed: any caller passing below them gets :class:`KeyDerivationError`.
Low-power-device callers must explicitly request a documented lower
profile rather than silently weakening security.

The :func:`info_for` helper enforces the project-wide HKDF info-string
convention so that derivations from the same shared secret in different
contexts (e.g. KEM-key vs MAC-key) cannot collide.
"""

from __future__ import annotations

from typing import Final, Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from qwashed.core.errors import KeyDerivationError

__all__ = [
    "ARGON2ID_DEFAULT_MEMORY_KIB",
    "ARGON2ID_DEFAULT_PARALLELISM",
    "ARGON2ID_DEFAULT_TIME_COST",
    "ARGON2ID_MIN_MEMORY_KIB",
    "ARGON2ID_MIN_PARALLELISM",
    "ARGON2ID_MIN_TIME_COST",
    "HKDF_SHA256_MAX_OUTPUT",
    "argon2id",
    "hkdf_sha256",
    "info_for",
]

#: HKDF-SHA256 output cap is 255 * HashLen = 255 * 32 = 8160 bytes (RFC 5869).
HKDF_SHA256_MAX_OUTPUT: Final[int] = 255 * 32

# Argon2id default parameters (vault).
ARGON2ID_DEFAULT_MEMORY_KIB: Final[int] = 65536  # 64 MiB
ARGON2ID_DEFAULT_TIME_COST: Final[int] = 3
ARGON2ID_DEFAULT_PARALLELISM: Final[int] = 1

# Argon2id minimums (fail-closed lower bound).
ARGON2ID_MIN_MEMORY_KIB: Final[int] = 19456  # OWASP minimum (~19 MiB)
ARGON2ID_MIN_TIME_COST: Final[int] = 2
ARGON2ID_MIN_PARALLELISM: Final[int] = 1


def hkdf_sha256(*, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Derive ``length`` bytes from ``ikm`` using HKDF-SHA256.

    Parameters
    ----------
    ikm:
        Input keying material. Must be non-empty. For KEM shared-secret
        inputs, the caller is responsible for concatenating components in
        a fixed order (e.g. ``ss_x25519 || ss_mlkem768``).
    salt:
        Cryptographic salt. May be empty (HKDF zeros it internally) but
        a non-empty salt is strongly recommended where one is available.
    info:
        Context / application-specific binding. Use :func:`info_for` to
        produce the canonical Qwashed info string for a given purpose.
    length:
        Desired output length in bytes. Must be in
        ``1..HKDF_SHA256_MAX_OUTPUT``.

    Returns
    -------
    bytes
        Exactly ``length`` bytes of derived keying material.

    Raises
    ------
    KeyDerivationError
        If ``ikm`` is empty, ``length`` is out of range, or the underlying
        primitive raises.
    """
    if not ikm:
        raise KeyDerivationError(
            "HKDF input keying material must not be empty",
            error_code="kdf.hkdf.empty_ikm",
        )
    if length < 1 or length > HKDF_SHA256_MAX_OUTPUT:
        raise KeyDerivationError(
            f"HKDF length must be in [1, {HKDF_SHA256_MAX_OUTPUT}], got {length}",
            error_code="kdf.hkdf.bad_length",
        )

    try:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        ).derive(ikm)
    except Exception as exc:  # pragma: no cover - defensive wrap
        raise KeyDerivationError(
            f"HKDF-SHA256 derivation failed: {exc}",
            error_code="kdf.hkdf.derive_failed",
        ) from exc


def argon2id(
    *,
    password: bytes,
    salt: bytes,
    memory_kib: int = ARGON2ID_DEFAULT_MEMORY_KIB,
    time_cost: int = ARGON2ID_DEFAULT_TIME_COST,
    parallelism: int = ARGON2ID_DEFAULT_PARALLELISM,
    length: int = 32,
) -> bytes:
    """Derive ``length`` bytes from ``password`` using Argon2id.

    Wrapper over ``argon2-cffi``'s low-level hasher. Imported lazily so that
    a Qwashed install without the ``[vault]`` extra can still import
    :mod:`qwashed.core.kdf` for HKDF-only callers.

    Parameters
    ----------
    password:
        Passphrase bytes (UTF-8 encoded externally; this layer is bytes).
        Must be non-empty.
    salt:
        Per-vault random salt. Must be at least 16 bytes.
    memory_kib:
        Memory cost in KiB. Must be >= ``ARGON2ID_MIN_MEMORY_KIB``.
    time_cost:
        Number of iterations. Must be >= ``ARGON2ID_MIN_TIME_COST``.
    parallelism:
        Number of lanes. Must be >= ``ARGON2ID_MIN_PARALLELISM``.
    length:
        Output length in bytes. Must be >= 16 (no AEAD key smaller than
        AES-128 worth of derived material).

    Returns
    -------
    bytes
        ``length`` bytes of derived keying material suitable for direct use
        as an AEAD key (or as IKM for a follow-up HKDF expansion).

    Raises
    ------
    KeyDerivationError
        On any parameter below the fail-closed minimum, or on underlying
        derivation failure.
    """
    if not password:
        raise KeyDerivationError(
            "Argon2id password must not be empty",
            error_code="kdf.argon2.empty_password",
        )
    if len(salt) < 16:
        raise KeyDerivationError(
            f"Argon2id salt must be at least 16 bytes, got {len(salt)}",
            error_code="kdf.argon2.short_salt",
        )
    if memory_kib < ARGON2ID_MIN_MEMORY_KIB:
        raise KeyDerivationError(
            f"Argon2id memory_kib must be >= {ARGON2ID_MIN_MEMORY_KIB}, got {memory_kib}",
            error_code="kdf.argon2.weak_memory",
        )
    if time_cost < ARGON2ID_MIN_TIME_COST:
        raise KeyDerivationError(
            f"Argon2id time_cost must be >= {ARGON2ID_MIN_TIME_COST}, got {time_cost}",
            error_code="kdf.argon2.weak_time",
        )
    if parallelism < ARGON2ID_MIN_PARALLELISM:
        raise KeyDerivationError(
            f"Argon2id parallelism must be >= {ARGON2ID_MIN_PARALLELISM}, got {parallelism}",
            error_code="kdf.argon2.weak_parallelism",
        )
    if length < 16:
        raise KeyDerivationError(
            f"Argon2id output length must be >= 16, got {length}",
            error_code="kdf.argon2.short_output",
        )

    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:
        raise KeyDerivationError(
            "argon2-cffi is required for Argon2id; install qwashed[vault]",
            error_code="kdf.argon2.missing_dep",
        ) from exc

    try:
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_kib,
            parallelism=parallelism,
            hash_len=length,
            type=Type.ID,
        )
    except Exception as exc:  # pragma: no cover - defensive wrap
        raise KeyDerivationError(
            f"Argon2id derivation failed: {exc}",
            error_code="kdf.argon2.derive_failed",
        ) from exc


def info_for(
    *,
    module: Literal["audit", "vault"],
    purpose: str,
    version: str = "v0.1",
) -> bytes:
    """Build a Qwashed-canonical HKDF info string.

    Format::

        b"qwashed/<module>/<version>/<purpose>"

    e.g. ``info_for(module="vault", purpose="kem")`` ->
    ``b"qwashed/vault/v0.1/kem"``.

    Different ``purpose`` values guarantee derivation domain separation:
    a key derived for ``"kem"`` cannot be the same as a key derived from
    the same IKM for ``"mac"`` even if all other inputs are identical.

    Raises
    ------
    KeyDerivationError
        If ``purpose`` is empty or contains a slash (which would let a
        caller forge a different module's namespace).
    """
    if not purpose:
        raise KeyDerivationError(
            "HKDF info purpose must not be empty",
            error_code="kdf.info.empty_purpose",
        )
    if "/" in purpose:
        raise KeyDerivationError(
            "HKDF info purpose must not contain '/' (namespace separator)",
            error_code="kdf.info.slash_in_purpose",
        )
    return f"qwashed/{module}/{version}/{purpose}".encode("ascii")
