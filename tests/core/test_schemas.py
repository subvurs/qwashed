# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.core.schemas."""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Annotated

import pytest
from pydantic import AfterValidator

from qwashed.core.errors import SchemaValidationError
from qwashed.core.schemas import (
    StrictBaseModel,
    b64_bytes,
    ed25519_pubkey_b64,
    mldsa65_pubkey_b64,
    nonempty_str,
    parse_strict,
    sha256_hex,
)


class _Probe(StrictBaseModel):
    host: Annotated[str, AfterValidator(nonempty_str)]
    port: int


class TestStrictBaseModel:
    def test_basic_construction(self) -> None:
        p = _Probe(host="example.com", port=443)
        assert p.host == "example.com"
        assert p.port == 443

    def test_extra_field_forbidden(self) -> None:
        with pytest.raises(Exception):
            _Probe(host="example.com", port=443, secret="x")  # type: ignore[call-arg]

    def test_frozen(self) -> None:
        p = _Probe(host="example.com", port=443)
        with pytest.raises(Exception):
            p.host = "evil.com"

    def test_strip_whitespace(self) -> None:
        p = _Probe(host="  example.com  ", port=443)
        assert p.host == "example.com"


class TestParseStrict:
    def test_success(self) -> None:
        p = parse_strict(_Probe, {"host": "example.com", "port": 443})
        assert p.host == "example.com"

    def test_failure_wraps_pydantic(self) -> None:
        with pytest.raises(SchemaValidationError) as exc:
            parse_strict(_Probe, {"host": "", "port": 443})
        assert exc.value.error_code == "schema.validation_failed"
        assert exc.value.pydantic_error is not None


class TestNonemptyStr:
    def test_accepts_text(self) -> None:
        assert nonempty_str("x") == "x"

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValueError):
            nonempty_str("")


class TestB64Bytes:
    def test_accepts_valid(self) -> None:
        encoded = base64.b64encode(b"hello").decode("ascii")
        assert b64_bytes(encoded) == encoded

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValueError):
            b64_bytes("")

    def test_rejects_invalid(self) -> None:
        with pytest.raises(ValueError):
            b64_bytes("not!base64@@@")


class TestSha256Hex:
    def test_accepts_valid(self) -> None:
        digest = hashlib.sha256(b"x").hexdigest()
        assert sha256_hex(digest) == digest

    def test_rejects_uppercase(self) -> None:
        digest = hashlib.sha256(b"x").hexdigest().upper()
        with pytest.raises(ValueError):
            sha256_hex(digest)

    def test_rejects_wrong_length(self) -> None:
        with pytest.raises(ValueError):
            sha256_hex("abc")


class TestEd25519PubkeyB64:
    def test_accepts_32_bytes(self) -> None:
        encoded = base64.b64encode(os.urandom(32)).decode("ascii")
        assert ed25519_pubkey_b64(encoded) == encoded

    def test_rejects_wrong_length(self) -> None:
        encoded = base64.b64encode(b"too short").decode("ascii")
        with pytest.raises(ValueError):
            ed25519_pubkey_b64(encoded)

    def test_rejects_bad_b64(self) -> None:
        with pytest.raises(ValueError):
            ed25519_pubkey_b64("@@@")


class TestMldsa65PubkeyB64:
    def test_accepts_correct_length(self) -> None:
        encoded = base64.b64encode(os.urandom(1952)).decode("ascii")
        assert mldsa65_pubkey_b64(encoded) == encoded

    def test_rejects_wrong_length(self) -> None:
        encoded = base64.b64encode(os.urandom(32)).decode("ascii")
        with pytest.raises(ValueError):
            mldsa65_pubkey_b64(encoded)
