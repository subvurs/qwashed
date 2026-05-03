# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.core.canonical (RFC 8785 canonical JSON)."""

from __future__ import annotations

import hashlib
import json

import pytest

from qwashed.core.canonical import canonical_hash, canonicalize
from qwashed.core.errors import CanonicalizationError


class TestPrimitives:
    def test_null(self) -> None:
        assert canonicalize(None) == b"null"

    def test_true_false(self) -> None:
        assert canonicalize(True) == b"true"
        assert canonicalize(False) == b"false"

    def test_integer(self) -> None:
        assert canonicalize(0) == b"0"
        assert canonicalize(-7) == b"-7"
        assert canonicalize(2**53) == b"9007199254740992"

    def test_float_integer_valued(self) -> None:
        assert canonicalize(1.0) == b"1"
        assert canonicalize(-2.0) == b"-2"
        assert canonicalize(0.0) == b"0"
        assert canonicalize(-0.0) == b"0"

    def test_float_fraction(self) -> None:
        # Python's repr for 0.5 is "0.5"; ECMA-262 agrees.
        assert canonicalize(0.5) == b"0.5"

    def test_float_nan_rejected(self) -> None:
        with pytest.raises(CanonicalizationError) as exc:
            canonicalize(float("nan"))
        assert exc.value.error_code == "canonical.nan"

    def test_float_inf_rejected(self) -> None:
        with pytest.raises(CanonicalizationError) as exc:
            canonicalize(float("inf"))
        assert exc.value.error_code == "canonical.infinity"

    def test_float_neg_inf_rejected(self) -> None:
        with pytest.raises(CanonicalizationError):
            canonicalize(float("-inf"))


class TestStrings:
    def test_simple(self) -> None:
        assert canonicalize("hello") == b'"hello"'

    def test_short_escapes(self) -> None:
        # All seven RFC 8259 short escapes.
        assert canonicalize('\b\t\n\f\r"\\') == b'"\\b\\t\\n\\f\\r\\"\\\\"'

    def test_unicode_control(self) -> None:
        # U+0001 is not in the short-escape set; must be \u0001.
        assert canonicalize("\x01") == b'"\\u0001"'

    def test_unicode_above_control(self) -> None:
        # U+0020 (space) is the first character emitted as-is.
        assert canonicalize(" ") == b'" "'

    def test_unicode_bmp_emoji(self) -> None:
        # U+2603 SNOWMAN: BMP, no escape needed.
        out = canonicalize("\u2603")
        assert out == '"\u2603"'.encode()

    def test_supplementary_character(self) -> None:
        # U+1F600 GRINNING FACE: surrogate pair sort key in object emission.
        out = canonicalize("\U0001f600")
        assert out == '"\U0001f600"'.encode()


class TestObjects:
    def test_empty(self) -> None:
        assert canonicalize({}) == b"{}"

    def test_single_key(self) -> None:
        assert canonicalize({"a": 1}) == b'{"a":1}'

    def test_keys_sorted_by_codepoint(self) -> None:
        # Insertion order b, a, c -> output a, b, c.
        assert canonicalize({"b": 2, "a": 1, "c": 3}) == b'{"a":1,"b":2,"c":3}'

    def test_keys_sorted_supplementary(self) -> None:
        # U+1F600 has UTF-16 representation D83D DE00, which sorts AFTER
        # any BMP character. So an entry with key "\U0001f600" must be
        # placed last after BMP keys.
        out = canonicalize({"\U0001f600": 1, "z": 2, "a": 3})
        assert out.startswith(b'{"a":3,"z":2,')
        assert out.endswith(b"}")

    def test_non_string_key_rejected(self) -> None:
        with pytest.raises(CanonicalizationError) as exc:
            canonicalize({1: "value"})
        assert exc.value.error_code == "canonical.non_string_key"


class TestArrays:
    def test_empty(self) -> None:
        assert canonicalize([]) == b"[]"

    def test_simple(self) -> None:
        assert canonicalize([1, 2, 3]) == b"[1,2,3]"

    def test_tuple_treated_as_array(self) -> None:
        assert canonicalize((1, 2, 3)) == b"[1,2,3]"

    def test_mixed_types(self) -> None:
        assert canonicalize([1, "two", None, True]) == b'[1,"two",null,true]'

    def test_preserves_order(self) -> None:
        assert canonicalize([3, 1, 2]) == b"[3,1,2]"


class TestNested:
    def test_object_in_array(self) -> None:
        assert canonicalize([{"b": 1, "a": 2}]) == b'[{"a":2,"b":1}]'

    def test_array_in_object(self) -> None:
        assert canonicalize({"x": [1, 2]}) == b'{"x":[1,2]}'


class TestErrorPaths:
    def test_unsupported_type(self) -> None:
        class Weird:
            pass

        with pytest.raises(CanonicalizationError) as exc:
            canonicalize(Weird())
        assert exc.value.error_code == "canonical.unsupported_type"

    def test_cycle_detected(self) -> None:
        a: list[object] = [1, 2]
        a.append(a)
        with pytest.raises(CanonicalizationError) as exc:
            canonicalize(a)
        assert exc.value.error_code == "canonical.cycle"

    def test_dict_cycle_detected(self) -> None:
        d: dict[str, object] = {}
        d["self"] = d
        with pytest.raises(CanonicalizationError) as exc:
            canonicalize(d)
        assert exc.value.error_code == "canonical.cycle"


class TestIdempotency:
    def test_idempotent(self) -> None:
        # Round-trip canonical -> json.loads -> canonical must be stable.
        original = {"b": 1, "a": [3, 2, 1], "c": {"y": True, "x": None}}
        first = canonicalize(original)
        round_trip = canonicalize(json.loads(first))
        assert first == round_trip

    def test_order_independent(self) -> None:
        a = canonicalize({"a": 1, "b": 2, "c": 3})
        b = canonicalize({"c": 3, "b": 2, "a": 1})
        assert a == b


class TestCanonicalHash:
    def test_sha256(self) -> None:
        # Hash of the canonical bytes of {} is sha256(b"{}").
        expected = hashlib.sha256(b"{}").hexdigest()
        assert canonical_hash({}) == expected

    def test_sha3_256(self) -> None:
        expected = hashlib.sha3_256(b"{}").hexdigest()
        assert canonical_hash({}, algo="sha3-256") == expected

    def test_unknown_algo(self) -> None:
        with pytest.raises(CanonicalizationError) as exc:
            canonical_hash({}, algo="md5")  # type: ignore[arg-type]
        assert exc.value.error_code == "canonical.bad_hash_algo"
