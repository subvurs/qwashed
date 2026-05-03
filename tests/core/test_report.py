# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.core.report."""

from __future__ import annotations

import pytest

from qwashed.core.errors import ConfigurationError
from qwashed.core.report import escape_html, mark_safe, render_html


class TestRenderHtml:
    def test_simple_substitution(self) -> None:
        out = render_html("Hello {{ name }}!", {"name": "Alice"})
        assert out == "Hello Alice!"

    def test_substitution_with_no_whitespace(self) -> None:
        out = render_html("{{name}}", {"name": "Alice"})
        assert out == "Alice"

    def test_html_escaped_by_default(self) -> None:
        out = render_html("<p>{{ msg }}</p>", {"msg": "<script>x</script>"})
        assert "&lt;script&gt;" in out
        assert "<script>" not in out

    def test_attribute_escaping(self) -> None:
        # The classic XSS sink: attribute injection.
        out = render_html('<a href="{{ url }}">x</a>', {"url": '" onclick="evil"'})
        assert 'onclick="evil"' not in out
        assert "&quot;" in out

    def test_safe_string_not_escaped(self) -> None:
        safe = mark_safe("<b>bold</b>")
        out = render_html("<p>{{ html }}</p>", {"html": safe})
        assert out == "<p><b>bold</b></p>"

    def test_int_value_coerced_to_str(self) -> None:
        out = render_html("count={{ n }}", {"n": 42})
        assert out == "count=42"

    def test_missing_placeholder_value_raises(self) -> None:
        with pytest.raises(ConfigurationError) as exc:
            render_html("{{ missing }}", {})
        assert exc.value.error_code == "report.unknown_placeholder"

    def test_unbalanced_braces_rejected(self) -> None:
        with pytest.raises(ConfigurationError) as exc:
            render_html("{{ name }} }} extra", {"name": "x"})
        assert exc.value.error_code == "report.unbalanced_braces"

    def test_malformed_placeholder_rejected(self) -> None:
        # {{ 1invalid }} - placeholder name cannot start with digit.
        with pytest.raises(ConfigurationError) as exc:
            render_html("{{ 1invalid }}", {"1invalid": "x"})
        assert exc.value.error_code == "report.bad_placeholder"


class TestEscapeHtml:
    def test_escapes_text(self) -> None:
        assert escape_html("a & b") == "a &amp; b"

    def test_escapes_quotes(self) -> None:
        assert escape_html('"').count("&quot;") == 1
