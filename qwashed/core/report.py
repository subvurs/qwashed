# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Lightweight HTML report scaffolding for Qwashed.

Why no Jinja2
-------------
Audit reports are tiny (one to a few hundred items) and the substitution
surface is correspondingly small. Pulling Jinja2 into the runtime
dependency set for that purpose would (a) bloat the install footprint of
a tool meant to run on civil-society laptops, (b) add an additional
attack surface, and (c) complicate the no-network test profile. Instead,
this module provides a deliberately small, deliberately strict template
substitution helper that:

* Refuses unknown placeholders (fail-closed; rejects template/data drift).
* HTML-escapes every substituted value by default. Callers that need raw
  HTML (e.g. an already-built ``<table>`` block) pass it via
  :func:`mark_safe`.
* Refuses templates that contain unbalanced ``{{ ... }}`` markers.

Public API
----------

* :func:`render_html` -- substitute ``{{ name }}`` placeholders.
* :func:`mark_safe` -- mark a value as already-escaped HTML.
* :func:`escape_html` -- explicit escaper for callers who build HTML
  fragments by hand.
* :func:`render_pdf` -- optional, requires ``qwashed[report]`` extra.

Future work
-----------
The PDF path is exposed here as a thin import-on-demand wrapper around
ReportLab. Rendering a PDF with the same fidelity as the HTML report is a
Phase 2 deliverable; this module just provides the entry point.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping
from typing import Final

from qwashed.core.errors import ConfigurationError

__all__ = [
    "SafeString",
    "escape_html",
    "mark_safe",
    "render_html",
    "render_pdf",
]

# Template syntax: {{ name }} (whitespace optional). Names match
# [A-Za-z_][A-Za-z0-9_]*. Anything else inside double-braces is rejected.
_PLACEHOLDER_RE: Final[re.Pattern[str]] = re.compile(
    r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}",
)
_BRACE_AUDIT_RE: Final[re.Pattern[str]] = re.compile(r"\{\{|\}\}")


class SafeString(str):
    """A string that has already been HTML-escaped (or never needed escaping).

    :func:`render_html` will substitute :class:`SafeString` instances
    verbatim. Build one via :func:`mark_safe`.
    """

    __slots__ = ()


def mark_safe(value: str) -> SafeString:
    """Mark ``value`` as already-safe HTML and skip escaping on substitution.

    Use sparingly: this is the single point where authors take
    responsibility for the safety of an HTML fragment.
    """
    return SafeString(value)


def escape_html(value: str) -> str:
    """HTML-escape ``value`` for safe inclusion in an HTML attribute or text.

    Wraps :func:`html.escape` with ``quote=True`` so the result is safe in
    both element text and attribute values.
    """
    return html.escape(value, quote=True)


def render_html(template: str, context: Mapping[str, object]) -> str:
    """Substitute ``{{ name }}`` placeholders in ``template``.

    Parameters
    ----------
    template:
        HTML template string. Placeholders use ``{{ name }}`` syntax; any
        un-paired ``{{`` or ``}}`` raises :class:`ConfigurationError`.
    context:
        Mapping of placeholder name to value. Values are converted to
        ``str`` (via ``str(value)``) and HTML-escaped unless they are
        :class:`SafeString` instances.

    Returns
    -------
    str
        Rendered HTML.

    Raises
    ------
    ConfigurationError
        If the template contains an unknown placeholder, an unsupported
        construct (e.g. a single brace), or unbalanced ``{{`` / ``}}``.
    """
    # 1. Audit balance: every {{ must be paired with a }} via the placeholder
    #    grammar; if the count of {{...}} markers does not match the count of
    #    successful placeholder matches, something is malformed.
    open_count = template.count("{{")
    close_count = template.count("}}")
    if open_count != close_count:
        raise ConfigurationError(
            f"unbalanced template braces: {open_count} '{{{{' vs {close_count} '}}}}'",
            error_code="report.unbalanced_braces",
        )

    matches = list(_PLACEHOLDER_RE.finditer(template))
    if len(matches) != open_count:
        # There is at least one {{ ... }} that does not match the
        # placeholder grammar. Locate the first offender to report it.
        scan = _PLACEHOLDER_RE.sub("", template)
        if "{{" in scan or "}}" in scan:
            raise ConfigurationError(
                "template contains malformed placeholder; expected '{{ name }}'",
                error_code="report.bad_placeholder",
            )

    # 2. Substitute. We use a function so we can fail on missing keys.
    def _substitute(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in context:
            raise ConfigurationError(
                f"template references unknown placeholder {name!r}",
                error_code="report.unknown_placeholder",
            )
        value = context[name]
        if isinstance(value, SafeString):
            return str(value)
        return escape_html(str(value))

    return _PLACEHOLDER_RE.sub(_substitute, template)


def render_pdf(html_content: str, output_path: str) -> None:
    """Render ``html_content`` to a PDF at ``output_path`` via ReportLab.

    This function lazily imports :mod:`reportlab` so that callers who only
    want HTML never pay the import cost or the ``qwashed[report]`` extra.
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate
    except ImportError as exc:
        raise ConfigurationError(
            "reportlab is required for PDF output; install qwashed[report]",
            error_code="report.missing_reportlab",
        ) from exc

    # Phase 1 PDF rendering is intentionally minimal: dump the HTML content
    # as a single Paragraph block. Rich layout arrives in Phase 2 with the
    # audit report templates that justify the complexity.
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    flowables = [Paragraph(html_content, styles["BodyText"])]
    doc.build(flowables)
