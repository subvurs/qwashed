# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.core.errors."""

from __future__ import annotations

import pytest

from qwashed.core.errors import (
    CanonicalizationError,
    ConfigurationError,
    KeyDerivationError,
    QwashedError,
    SchemaValidationError,
    SignatureError,
)


class TestQwashedError:
    def test_base_class_carries_default_code(self) -> None:
        err = QwashedError("boom")
        assert err.error_code == "qwashed.unknown"
        assert str(err) == "boom"

    def test_explicit_code_overrides_default(self) -> None:
        err = QwashedError("boom", error_code="explicit.thing")
        assert err.error_code == "explicit.thing"

    def test_inheritance_chain(self) -> None:
        for cls in (
            CanonicalizationError,
            SignatureError,
            KeyDerivationError,
            SchemaValidationError,
            ConfigurationError,
        ):
            assert issubclass(cls, QwashedError)
            assert issubclass(cls, Exception)

    def test_each_subclass_has_distinct_default_code(self) -> None:
        codes = {
            CanonicalizationError.default_error_code,
            SignatureError.default_error_code,
            KeyDerivationError.default_error_code,
            SchemaValidationError.default_error_code,
            ConfigurationError.default_error_code,
        }
        assert len(codes) == 5

    def test_catching_base_catches_subclass(self) -> None:
        with pytest.raises(QwashedError):
            raise SignatureError("nope")


class TestSchemaValidationError:
    def test_carries_underlying_pydantic_error(self) -> None:
        underlying = ValueError("inner")
        err = SchemaValidationError("outer", pydantic_error=underlying)
        assert err.pydantic_error is underlying

    def test_pydantic_error_defaults_to_none(self) -> None:
        err = SchemaValidationError("outer")
        assert err.pydantic_error is None
