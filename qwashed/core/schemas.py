# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Pydantic v2 base patterns and reusable validators for Qwashed.

Design choices
--------------
* :class:`StrictBaseModel` is the project's only base model. It is frozen
  (post-construction mutation raises) and forbids extra fields. Any model
  that does not inherit from it is a bug.
* Validation errors raised by user-supplied data are converted to
  :class:`SchemaValidationError` so callers do not have to import pydantic
  to handle Qwashed errors.
* Reusable validators are exposed as functions; bind them with
  :func:`pydantic.AfterValidator` rather than writing custom
  ``model_validator`` blocks per model.

Examples
--------
>>> from typing import Annotated
>>> from pydantic import AfterValidator
>>> class Probe(StrictBaseModel):
...     host: Annotated[str, AfterValidator(nonempty_str)]
...     port: int
>>> Probe(host="example.com", port=443).host
'example.com'
"""

from __future__ import annotations

import base64
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from qwashed.core.errors import SchemaValidationError

__all__ = [
    "StrictBaseModel",
    "b64_bytes",
    "ed25519_pubkey_b64",
    "mldsa65_pubkey_b64",
    "nonempty_str",
    "parse_strict",
    "sha256_hex",
]

#: Public-key sizes in bytes for the algorithms Qwashed signs with.
_ED25519_PUBKEY_LEN = 32
_MLDSA65_PUBKEY_LEN = 1952  # FIPS 204 ML-DSA-65 public key length

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class StrictBaseModel(BaseModel):
    """Frozen, extra-forbidding pydantic base model.

    Subclasses inherit:

    * ``extra="forbid"`` -- unexpected fields raise instead of being silently
      dropped. Forbids the ``{"version": "0.1", "tracker_url": "..."}``
      pattern that has bitten audited products before.
    * ``frozen=True`` -- post-construction mutation raises. Models hold
      validated data; if the data needs to change, build a new model.
    * ``str_strip_whitespace=True`` -- defensive, harmless, prevents the
      classic ``" admin"`` vs ``"admin"`` mismatch.
    * ``validate_assignment=True`` -- belt-and-suspenders for the rare case
      where ``frozen=True`` is intentionally relaxed in a subclass.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        validate_assignment=True,
    )


def parse_strict(model: type[BaseModel], data: Any) -> Any:
    """Parse ``data`` against ``model`` and convert pydantic errors.

    Wraps ``model.model_validate(data)`` so that callers see
    :class:`SchemaValidationError` (a Qwashed error) instead of having to
    import pydantic just to catch validation failures.
    """
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise SchemaValidationError(
            f"validation failed for {model.__name__}: {exc.error_count()} error(s)",
            error_code="schema.validation_failed",
            pydantic_error=exc,
        ) from exc


# ---------------------------------------------------------------------------
# Reusable validators (use with pydantic.AfterValidator).
# ---------------------------------------------------------------------------


def nonempty_str(value: str) -> str:
    """Reject empty / whitespace-only strings.

    The :class:`StrictBaseModel` ``str_strip_whitespace=True`` setting has
    already stripped leading/trailing whitespace by the time this runs, so
    a pure-whitespace input arrives here as ``""``.
    """
    if not value:
        raise ValueError("string must not be empty")
    return value


def b64_bytes(value: str) -> str:
    """Validate that ``value`` is correctly-padded standard base64.

    Returns the original string unchanged on success; the model can decode
    on demand. Standard base64 only -- URL-safe variant (``-`` / ``_``)
    must be declared explicitly per-field if needed.
    """
    if not value:
        raise ValueError("base64 string must not be empty")
    try:
        base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise ValueError(f"not valid base64: {exc}") from exc
    return value


def sha256_hex(value: str) -> str:
    """Validate that ``value`` is a 64-character lowercase SHA-256 hex digest."""
    if not _SHA256_HEX_RE.match(value):
        raise ValueError(
            "must be a 64-character lowercase hex SHA-256 digest",
        )
    return value


def ed25519_pubkey_b64(value: str) -> str:
    """Validate base64-encoded Ed25519 public key (32 raw bytes)."""
    decoded = _decode_b64_or_raise(value, field="ed25519 public key")
    if len(decoded) != _ED25519_PUBKEY_LEN:
        raise ValueError(
            f"ed25519 public key must decode to {_ED25519_PUBKEY_LEN} bytes, got {len(decoded)}",
        )
    return value


def mldsa65_pubkey_b64(value: str) -> str:
    """Validate base64-encoded ML-DSA-65 public key (FIPS 204 length)."""
    decoded = _decode_b64_or_raise(value, field="ML-DSA-65 public key")
    if len(decoded) != _MLDSA65_PUBKEY_LEN:
        raise ValueError(
            f"ML-DSA-65 public key must decode to {_MLDSA65_PUBKEY_LEN} bytes, got {len(decoded)}",
        )
    return value


def _decode_b64_or_raise(value: str, *, field: str) -> bytes:
    if not value:
        raise ValueError(f"{field} must not be empty")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise ValueError(f"{field} is not valid base64: {exc}") from exc
