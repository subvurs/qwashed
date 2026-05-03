# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Typed exception hierarchy for Qwashed.

All Qwashed errors inherit from :class:`QwashedError`. Each carries a stable
:attr:`error_code` string so downstream code can branch on a machine-readable
identifier rather than parsing the human-readable message.

Fail-closed posture: every public function in ``qwashed.core`` (and the
modules built on top of it) MUST raise one of these on any error path. Silent
``return None`` / ``return False`` / best-effort fallback is a contract
violation and a security bug.

Examples
--------
>>> try:
...     raise SchemaValidationError("bad target", error_code="schema.target")
... except QwashedError as exc:
...     exc.error_code
'schema.target'
"""

from __future__ import annotations

from typing import ClassVar

__all__ = [
    "CanonicalizationError",
    "ConfigurationError",
    "KeyDerivationError",
    "QwashedError",
    "SchemaValidationError",
    "SignatureError",
]


class QwashedError(Exception):
    """Base class for every Qwashed-raised exception.

    Never raise :class:`QwashedError` directly; raise one of its subclasses.
    Catching :class:`QwashedError` is the canonical way to handle "any
    Qwashed-domain failure" without swallowing unrelated exceptions.

    Parameters
    ----------
    message:
        Human-readable description of the failure. Should be safe to log
        (no key material, no passphrases, no plaintext).
    error_code:
        Stable machine-readable identifier of the form
        ``"<module>.<reason>"`` (e.g. ``"signing.bad_signature"``). Downstream
        code is encouraged to branch on this rather than ``message``.
    """

    #: Default error code; subclasses override.
    default_error_code: ClassVar[str] = "qwashed.unknown"

    def __init__(self, message: str, *, error_code: str | None = None) -> None:
        super().__init__(message)
        self.error_code: str = error_code or self.default_error_code

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"{type(self).__name__}({self.args[0]!r}, error_code={self.error_code!r})"


class CanonicalizationError(QwashedError):
    """RFC 8785 canonicalization failed.

    Raised by :func:`qwashed.core.canonical.canonicalize` when the input
    cannot be expressed as canonical JSON (e.g. NaN, Infinity, non-string
    object keys, recursive structures, non-finite floats, types that JSON
    has no representation for).
    """

    default_error_code = "canonical.invalid_input"


class SignatureError(QwashedError):
    """Cryptographic signing or verification failed.

    Includes: malformed signature blob, malformed key, signature/key length
    mismatch, signature verification returned ``False``, hybrid component
    mismatch.
    """

    default_error_code = "signing.invalid"


class KeyDerivationError(QwashedError):
    """A KDF (HKDF, Argon2id) refused its input or produced no output.

    Includes: zero-length input keying material, requested output length
    above the algorithm's per-call cap, Argon2id parameters below the
    fail-closed minimum.
    """

    default_error_code = "kdf.invalid"


class SchemaValidationError(QwashedError):
    """A pydantic model rejected the supplied data.

    Wraps the underlying :class:`pydantic.ValidationError` (when present)
    on the :attr:`pydantic_error` attribute so callers can inspect the
    individual field errors without re-running validation.
    """

    default_error_code = "schema.invalid"

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        pydantic_error: Exception | None = None,
    ) -> None:
        super().__init__(message, error_code=error_code)
        self.pydantic_error: Exception | None = pydantic_error


class ConfigurationError(QwashedError):
    """A user-supplied configuration file or CLI flag combination is invalid.

    Distinct from :class:`SchemaValidationError`: schema errors come from
    pydantic on raw input parsing; configuration errors come from
    higher-level checks (e.g. "audit profile name does not exist",
    "output path is not writable").
    """

    default_error_code = "config.invalid"
