# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""RFC 8785 (JCS) canonical JSON serialization.

Why this matters
----------------
Every signed artifact Qwashed produces (audit reports, vault audit-log
lines, vault entry metadata) is signed over the *canonical* byte sequence
of its JSON payload. Without canonicalization, two semantically identical
JSON objects can serialize to different byte strings and produce different
signatures, which would (a) make verification non-deterministic and
(b) defeat the ``--deterministic`` reproducibility guarantee.

RFC 8785 specifies a single canonical form:

* UTF-8 encoding with no BOM.
* Object members sorted lexicographically by their UTF-16 code unit
  representation (which, for the BMP, matches Python's default code-point
  ordering on ``str``).
* No insignificant whitespace.
* Numbers serialized per ECMA-262 ``Number.prototype.toString``: integers
  render without a fractional part; non-integer finite floats use the
  shortest round-tripping decimal; ``NaN`` and ``±Infinity`` are not
  representable and MUST cause :class:`CanonicalizationError`.
* String escaping limited to the JSON-mandatory set
  (``\\"``, ``\\\\``, ``\\b``, ``\\f``, ``\\n``, ``\\r``, ``\\t``,
  ``\\u00XX`` for U+0000..U+001F).

Public API
----------

* :func:`canonicalize` -- serialize a Python object to canonical JSON bytes.
* :func:`canonical_hash` -- canonicalize and hash with SHA-256 or SHA3-256.

Both raise :class:`CanonicalizationError` on any failure. Silent fallback
is a contract violation.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any, Final, Literal

from qwashed.core.errors import CanonicalizationError

__all__ = ["canonical_hash", "canonicalize"]

# Hash algorithms we will sign over. SHA-256 is the workhorse; SHA3-256 is
# offered for callers who want a different family for cross-checking.
_HashAlgo = Literal["sha256", "sha3-256"]

#: JSON-mandatory short escapes, per RFC 8259 sec. 7.
_SHORT_ESCAPES: Final[dict[int, str]] = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def canonicalize(obj: Any) -> bytes:
    """Serialize ``obj`` to canonical JSON bytes per RFC 8785.

    Parameters
    ----------
    obj:
        Any combination of ``dict[str, ...]``, ``list``, ``tuple``,
        ``str``, ``int``, ``float``, ``bool``, ``None``. Tuples are
        treated as JSON arrays.

    Returns
    -------
    bytes
        The canonical UTF-8 byte sequence.

    Raises
    ------
    CanonicalizationError
        On any input that has no canonical representation: ``NaN``,
        ``±Infinity``, non-string dict keys, unsupported types, or
        cycles in the graph.
    """
    seen: set[int] = set()
    parts: list[str] = []
    _emit(obj, parts, seen)
    return "".join(parts).encode("utf-8")


def canonical_hash(obj: Any, algo: _HashAlgo = "sha256") -> str:
    """Canonicalize ``obj`` and return the hex digest.

    Parameters
    ----------
    obj:
        Object to canonicalize.
    algo:
        ``"sha256"`` (default) or ``"sha3-256"``.

    Returns
    -------
    str
        Lowercase hex digest.

    Raises
    ------
    CanonicalizationError
        On canonicalization failure, or if ``algo`` is unrecognized.
    """
    payload = canonicalize(obj)
    if algo == "sha256":
        return hashlib.sha256(payload).hexdigest()
    if algo == "sha3-256":
        return hashlib.sha3_256(payload).hexdigest()
    raise CanonicalizationError(
        f"unsupported hash algorithm: {algo!r}",
        error_code="canonical.bad_hash_algo",
    )


# ---------------------------------------------------------------------------
# Internal emission helpers. These are intentionally private; the public
# contract is "give us an object, get bytes back" and nothing more.
# ---------------------------------------------------------------------------


def _emit(obj: Any, out: list[str], seen: set[int]) -> None:
    """Recursive emitter. Appends canonical fragments to ``out``.

    Cycle detection is by ``id(obj)`` for containers only; primitives are
    intentionally exempt because they can repeat freely without cycles.
    """
    if obj is None:
        out.append("null")
        return
    if obj is True:
        out.append("true")
        return
    if obj is False:
        out.append("false")
        return

    if isinstance(obj, str):
        out.append(_emit_string(obj))
        return

    if isinstance(obj, bool):  # pragma: no cover - covered by 'is True/False' above
        # Defensive: bool is subclass of int in Python; we already returned
        # above, so this branch should be unreachable, but keep it for safety
        # against subclassed bools or future Python changes.
        out.append("true" if obj else "false")
        return

    if isinstance(obj, int):
        out.append(_emit_integer(obj))
        return

    if isinstance(obj, float):
        out.append(_emit_float(obj))
        return

    container_id = id(obj)
    if container_id in seen:
        raise CanonicalizationError(
            "cycle detected in input object graph",
            error_code="canonical.cycle",
        )

    if isinstance(obj, dict):
        seen.add(container_id)
        try:
            _emit_object(obj, out, seen)
        finally:
            seen.discard(container_id)
        return

    if isinstance(obj, (list, tuple)):
        seen.add(container_id)
        try:
            _emit_array(obj, out, seen)
        finally:
            seen.discard(container_id)
        return

    raise CanonicalizationError(
        f"type {type(obj).__name__!r} has no canonical JSON representation",
        error_code="canonical.unsupported_type",
    )


def _emit_object(obj: dict[Any, Any], out: list[str], seen: set[int]) -> None:
    """Emit a JSON object with RFC 8785-sorted keys.

    RFC 8785 requires lexicographic sorting on the UTF-16 code unit
    representation of each key. For all keys in the BMP this matches
    Python's default ``str`` ordering. For keys with code points
    >= U+10000 we explicitly compute the UTF-16 representation to remain
    spec-conformant on supplementary characters.
    """
    items: list[tuple[str, Any]] = []
    for key, value in obj.items():
        if not isinstance(key, str):
            raise CanonicalizationError(
                f"object key must be str, got {type(key).__name__}",
                error_code="canonical.non_string_key",
            )
        items.append((key, value))

    items.sort(key=lambda kv: _utf16_codeunits(kv[0]))

    out.append("{")
    first = True
    for key, value in items:
        if not first:
            out.append(",")
        first = False
        out.append(_emit_string(key))
        out.append(":")
        _emit(value, out, seen)
    out.append("}")


def _emit_array(arr: list[Any] | tuple[Any, ...], out: list[str], seen: set[int]) -> None:
    out.append("[")
    first = True
    for item in arr:
        if not first:
            out.append(",")
        first = False
        _emit(item, out, seen)
    out.append("]")


def _emit_string(value: str) -> str:
    """Encode ``value`` per RFC 8785 sec. 3.2.2.2 (string literal)."""
    parts: list[str] = ['"']
    for ch in value:
        cp = ord(ch)
        short = _SHORT_ESCAPES.get(cp)
        if short is not None:
            parts.append(short)
        elif cp < 0x20:
            parts.append(f"\\u{cp:04x}")
        else:
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


def _emit_integer(value: int) -> str:
    """Emit a Python ``int`` as a canonical JSON number.

    RFC 8785 mandates ECMA-262 number serialization. For integers this is
    the decimal representation with no leading zeros and no fractional
    part. Python's ``str(int)`` produces exactly that for any int that
    fits the IEEE-754 doubly-precise integer range. Larger ints serialize
    correctly as decimal text but are not round-trippable through
    JavaScript; we accept them here because Python's JSON ecosystem does,
    and document the loss-of-fidelity caveat.
    """
    return str(value)


def _emit_float(value: float) -> str:
    """Emit a Python ``float`` per ECMA-262 ``Number.prototype.toString``.

    Python's ``repr(float)`` is the shortest round-tripping decimal since
    3.1, which matches ECMA-262 for any finite value representable in
    IEEE-754 binary64. The exact text is *not* identical to JavaScript in
    every edge case (e.g. trailing ``.0`` differences), so we normalize:

    - Integer-valued floats serialize without a fractional part: ``1.0`` ->
      ``"1"``. This matches RFC 8785 sec. 3.2.2.3.
    - Non-finite (``NaN``, ``±Infinity``) is rejected.
    - Negative zero ``-0.0`` serializes as ``"0"`` per ECMA-262
      ``Number.prototype.toString`` (which strips the sign on zero).
    """
    if math.isnan(value):
        raise CanonicalizationError(
            "NaN has no canonical JSON representation",
            error_code="canonical.nan",
        )
    if math.isinf(value):
        raise CanonicalizationError(
            "Infinity has no canonical JSON representation",
            error_code="canonical.infinity",
        )

    # Negative zero -> "0".
    if value == 0.0:
        return "0"

    # Integer-valued floats render without a fractional part.
    if value.is_integer() and abs(value) < 1e16:
        return str(int(value))

    # Shortest round-tripping decimal. Python's repr already does this.
    text = repr(value)

    # Normalize exponent form: Python emits "1e-05"; ECMA-262 emits "1e-5".
    # RFC 8785 specifically aligns with ECMA-262, so strip a leading zero
    # in the exponent if present.
    if "e" in text:
        mantissa, _, exponent = text.partition("e")
        if exponent.startswith("+"):
            exponent = exponent[1:]
        if exponent.startswith("-0") and len(exponent) > 2:
            exponent = "-" + exponent[2:].lstrip("0")
            if exponent == "-":
                exponent = "0"
        elif exponent.startswith("0") and len(exponent) > 1:
            exponent = exponent.lstrip("0") or "0"
        text = f"{mantissa}e{exponent}"

    return text


def _utf16_codeunits(s: str) -> tuple[int, ...]:
    """Return the UTF-16 code-unit sequence of ``s`` as a tuple of ints.

    For BMP characters this is just ``(ord(c) for c in s)``. For
    supplementary characters (cp >= U+10000) we emit the surrogate pair
    so that sorting matches RFC 8785 / JavaScript ``String.prototype <``.
    """
    units: list[int] = []
    for ch in s:
        cp = ord(ch)
        if cp < 0x10000:
            units.append(cp)
        else:
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
    return tuple(units)
