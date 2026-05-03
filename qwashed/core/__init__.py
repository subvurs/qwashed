# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Shared infrastructure used by both ``qwashed.audit`` and ``qwashed.vault``.

This package is intentionally small. It contains only those primitives that
are generic enough to belong in a "core" layer:

- :mod:`qwashed.core.canonical` -- RFC 8785 canonical JSON serialization.
- :mod:`qwashed.core.signing`   -- Ed25519 signing wrapper.
- :mod:`qwashed.core.schemas`   -- Pydantic base patterns and fail-closed validators.
- :mod:`qwashed.core.kdf`       -- HKDF-SHA256 and Argon2id wrappers.
- :mod:`qwashed.core.report`    -- HTML report scaffolding (PDF via optional reportlab).
- :mod:`qwashed.core.errors`    -- Typed exceptions with fail-closed semantics.

These modules are reimplemented for Qwashed rather than imported from any
sibling project, to keep Qwashed's licensing and release cadence independent.
"""

from __future__ import annotations

from qwashed.core.canonical import canonical_hash, canonicalize
from qwashed.core.errors import (
    CanonicalizationError,
    ConfigurationError,
    KeyDerivationError,
    QwashedError,
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
from qwashed.core.report import (
    SafeString,
    escape_html,
    mark_safe,
    render_html,
    render_pdf,
)
from qwashed.core.schemas import (
    StrictBaseModel,
    b64_bytes,
    ed25519_pubkey_b64,
    mldsa65_pubkey_b64,
    nonempty_str,
    parse_strict,
    sha256_hex,
)
from qwashed.core.signing import (
    ED25519_PUBKEY_LEN,
    ED25519_SIGNATURE_LEN,
    SigningKey,
    VerifyKey,
)

__all__ = [
    "ARGON2ID_DEFAULT_MEMORY_KIB",
    "ARGON2ID_DEFAULT_PARALLELISM",
    "ARGON2ID_DEFAULT_TIME_COST",
    "ED25519_PUBKEY_LEN",
    "ED25519_SIGNATURE_LEN",
    "CanonicalizationError",
    "ConfigurationError",
    "KeyDerivationError",
    "QwashedError",
    "SafeString",
    "SchemaValidationError",
    "SignatureError",
    "SigningKey",
    "StrictBaseModel",
    "VerifyKey",
    "argon2id",
    "b64_bytes",
    "canonical_hash",
    "canonicalize",
    "ed25519_pubkey_b64",
    "escape_html",
    "hkdf_sha256",
    "info_for",
    "mark_safe",
    "mldsa65_pubkey_b64",
    "nonempty_str",
    "parse_strict",
    "render_html",
    "render_pdf",
    "sha256_hex",
]
