# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""``qwashed audit`` command-line interface.

Subcommands
-----------
* ``qwashed audit run <config>`` -- probe targets, classify, score, and
  emit a signed JSON report (and optional HTML/PDF render).
* ``qwashed audit profiles`` -- list bundled threat profiles.

The audit configuration file is YAML with the following shape::

    targets:
      - host: example.org
        port: 443
        protocol: tls            # default: tls
        label: example-prod      # optional
      - host: 10.0.0.5
        port: 22
        protocol: ssh

The CLI is the single point that touches the filesystem and the network.
Pure logic lives in :mod:`qwashed.audit.pipeline`, the probes, and the
classifier; this module orchestrates I/O, signing, and exit codes.

Exit codes
----------
* ``0`` -- audit ran successfully, report written.
* ``1`` -- audit ran but at least one finding was scored ``critical``;
  intentionally distinct from "structural error" so wrapper scripts can
  fail-fast on the bad-posture case.
* ``2`` -- structural error (bad config, profile load failure, signing
  key missing, I/O failure).
"""

from __future__ import annotations

import argparse
import base64
import datetime
import sys
from pathlib import Path
from typing import Any

from qwashed import __version__
from qwashed.audit.pipeline import run_audit
from qwashed.audit.probe import (
    DEFAULT_TIMEOUT_SECONDS,
    NativeTlsProbe,
    Probe,
    SslyzeTlsProbe,
    StdlibTlsProbe,
)
from qwashed.audit.profile_loader import (
    available_profiles,
    load_profile,
    load_profile_from_path,
)
from qwashed.audit.report_html import render_audit_html
from qwashed.audit.schemas import AuditTarget, ThreatProfile
from qwashed.core.canonical import canonicalize
from qwashed.core.errors import ConfigurationError, QwashedError
from qwashed.core.report import render_pdf
from qwashed.core.schemas import parse_strict
from qwashed.core.signing import SigningKey

__all__ = [
    "build_audit_parser",
    "run_audit_subcommand",
]


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def _yaml_safe_load(text: str) -> Any:
    """Lazy-import PyYAML so plain ``qwashed --version`` does not pay for it."""
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - depends on env
        raise ConfigurationError(
            "PyYAML is required to load audit configs; install qwashed[audit]",
            error_code="audit.cli.missing_yaml",
        ) from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"YAML parse error in audit config: {exc}",
            error_code="audit.cli.bad_yaml",
        ) from exc


def _load_targets(config_path: Path) -> list[AuditTarget]:
    """Parse an audit config file and return the validated target list."""
    if not config_path.is_file():
        raise ConfigurationError(
            f"audit config not found: {config_path}",
            error_code="audit.cli.config_missing",
        )
    text = config_path.read_text(encoding="utf-8")
    data = _yaml_safe_load(text)
    if not isinstance(data, dict):
        raise ConfigurationError(
            f"audit config {config_path} must be a YAML mapping",
            error_code="audit.cli.config_not_mapping",
        )
    raw_targets = data.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ConfigurationError(
            f"audit config {config_path} must define a non-empty 'targets' list",
            error_code="audit.cli.no_targets",
        )
    targets: list[AuditTarget] = []
    for entry in raw_targets:
        if not isinstance(entry, dict):
            raise ConfigurationError(
                f"each entry in 'targets' must be a mapping, got {type(entry).__name__}",
                error_code="audit.cli.bad_target_entry",
            )
        target = parse_strict(AuditTarget, entry)
        assert isinstance(target, AuditTarget)
        targets.append(target)
    return targets


# ---------------------------------------------------------------------------
# Signing helpers
# ---------------------------------------------------------------------------


def _load_or_generate_signing_key(
    *,
    key_path: Path | None,
    deterministic: bool,
) -> SigningKey:
    """Load an Ed25519 signing key from ``key_path`` or generate one.

    In ``--deterministic`` mode with no key path, a fixed all-zero seed
    is used. This is documented as a *test-only* default; production
    users always provide ``--signing-key``. The all-zero seed is used
    because deterministic output requires a deterministic key, and
    rejecting unsigned reports outright would break the equally
    important "this report was not tampered with after generation"
    workflow.
    """
    if key_path is not None:
        try:
            raw = key_path.read_bytes()
        except OSError as exc:
            raise ConfigurationError(
                f"cannot read signing key file {key_path}: {exc}",
                error_code="audit.cli.signing_key_io",
            ) from exc
        # Accept either raw 32 bytes or base64. Fail-closed if neither.
        if len(raw) == 32:
            return SigningKey.from_bytes(raw)
        try:
            text = raw.decode("ascii").strip()
            decoded = base64.b64decode(text, validate=True)
        except Exception as exc:
            raise ConfigurationError(
                f"signing key file {key_path} must be 32 raw bytes or base64",
                error_code="audit.cli.signing_key_format",
            ) from exc
        return SigningKey.from_bytes(decoded)

    if deterministic:
        return SigningKey.from_bytes(b"\x00" * 32)

    return SigningKey.generate()


def _sign_report(
    report_payload: dict[str, Any],
    signing_key: SigningKey,
) -> dict[str, Any]:
    """Return ``report_payload`` augmented with Ed25519 signature fields.

    Mirrors the envelope ``qwashed verify`` checks: the signature covers
    the canonicalization of the payload with the ``signature_ed25519``
    field stripped (the pubkey is part of the signed payload because a
    forger needs to be unable to swap pubkeys silently).
    """
    payload_for_sig = {k: v for k, v in report_payload.items() if k != "signature_ed25519"}
    payload_bytes = canonicalize(payload_for_sig)
    sig = signing_key.sign(payload_bytes)
    signed = dict(report_payload)
    signed["signature_ed25519"] = base64.b64encode(sig).decode("ascii")
    return signed


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def _profile_for_args(args: argparse.Namespace) -> ThreatProfile:
    if args.profile_file:
        return load_profile_from_path(args.profile_file)
    return load_profile(args.profile)


def _probe_for_args(args: argparse.Namespace) -> Probe:
    """Construct the probe implementation requested by the CLI.

    Default is ``NativeTlsProbe`` (Qwashed v0.2): full PQ posture with
    only stdlib + ``cryptography``, no extras required. ``stdlib`` is the
    legacy Python-``ssl`` probe (no KEX / no signature visibility) and
    is kept for callers in air-gapped environments. ``sslyze`` requires
    the ``[audit-deep]`` extra.
    """
    timeout = float(getattr(args, "probe_timeout", DEFAULT_TIMEOUT_SECONDS))
    selected = getattr(args, "probe", "native")
    if selected == "native":
        return NativeTlsProbe(timeout_seconds=timeout)
    if selected == "stdlib":
        return StdlibTlsProbe(timeout_seconds=timeout)
    if selected == "sslyze":
        return SslyzeTlsProbe(timeout_seconds=timeout)
    raise ConfigurationError(
        f"unknown probe implementation {selected!r}; expected one of native|stdlib|sslyze",
        error_code="audit.cli.bad_probe",
    )


def _frozen_timestamp(deterministic: bool) -> str:
    if deterministic:
        return "2026-01-01T00:00:00Z"
    now = datetime.datetime.now(datetime.UTC)
    # ISO 8601 with 'Z' suffix; matches the schema validator's expectations.
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _frozen_version(deterministic: bool) -> str:
    return "0.1.0" if deterministic else __version__


def _audit_run(args: argparse.Namespace) -> int:
    """Implement ``qwashed audit run <config>``."""
    config_path = Path(args.config)
    out_json = Path(args.output) if args.output else None
    out_html = Path(args.html) if args.html else None
    out_pdf = Path(args.pdf) if args.pdf else None
    deterministic = bool(args.deterministic)

    try:
        targets = _load_targets(config_path)
        profile = _profile_for_args(args)
        probe_impl = _probe_for_args(args)
    except QwashedError as exc:
        sys.stderr.write(f"qwashed audit: {exc} ({exc.error_code})\n")
        return 2

    try:
        signing_key = _load_or_generate_signing_key(
            key_path=Path(args.signing_key) if args.signing_key else None,
            deterministic=deterministic,
        )
    except QwashedError as exc:
        sys.stderr.write(f"qwashed audit: {exc} ({exc.error_code})\n")
        return 2

    try:
        report = run_audit(
            targets,
            profile=profile,
            probe_impl=probe_impl,
            generated_at=_frozen_timestamp(deterministic),
            qwashed_version=_frozen_version(deterministic),
        )
    except QwashedError as exc:
        sys.stderr.write(f"qwashed audit: pipeline error: {exc} ({exc.error_code})\n")
        return 2

    # JSON envelope: report fields + ed25519_pubkey + signature_ed25519.
    payload = report.model_dump(mode="json")
    payload["ed25519_pubkey"] = signing_key.verify_key.to_b64()
    try:
        signed = _sign_report(payload, signing_key)
    except QwashedError as exc:
        sys.stderr.write(f"qwashed audit: signing failed: {exc} ({exc.error_code})\n")
        return 2

    # Always render the JSON. Use canonicalize for byte-stable output so
    # --deterministic gives bit-identical files across runs.
    try:
        json_bytes = canonicalize(signed)
    except QwashedError as exc:
        sys.stderr.write(f"qwashed audit: canonicalization failed: {exc}\n")
        return 2

    if out_json is not None:
        try:
            out_json.write_bytes(json_bytes)
        except OSError as exc:
            sys.stderr.write(f"qwashed audit: cannot write {out_json}: {exc}\n")
            return 2
    else:
        sys.stdout.buffer.write(json_bytes)
        sys.stdout.buffer.write(b"\n")

    if out_html is not None:
        try:
            html = render_audit_html(
                report,
                pubkey_fingerprint=signing_key.verify_key.to_b64(),
            )
            out_html.write_text(html, encoding="utf-8")
        except (QwashedError, OSError) as exc:
            sys.stderr.write(f"qwashed audit: HTML render failed: {exc}\n")
            return 2

    if out_pdf is not None:
        try:
            html = render_audit_html(
                report,
                pubkey_fingerprint=signing_key.verify_key.to_b64(),
            )
            render_pdf(html, str(out_pdf))
        except (QwashedError, OSError) as exc:
            sys.stderr.write(f"qwashed audit: PDF render failed: {exc}\n")
            return 2

    # Exit code 1 if any finding is critical (and 0 otherwise).
    if any(f.severity == "critical" for f in report.findings):
        return 1
    return 0


def _audit_profiles(args: argparse.Namespace) -> int:
    """Implement ``qwashed audit profiles``: list built-in threat profiles."""
    del args  # unused
    names = available_profiles()
    if not names:
        sys.stderr.write("qwashed audit profiles: no built-in profiles found\n")
        return 2
    for name in names:
        try:
            profile = load_profile(name)
            sys.stdout.write(f"{name}: {profile.description}\n")
        except QwashedError as exc:
            sys.stdout.write(f"{name}: <load failed: {exc}>\n")
    return 0


# ---------------------------------------------------------------------------
# Argparse wiring
# ---------------------------------------------------------------------------


def build_audit_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Attach the ``audit`` subcommand tree to a top-level parser.

    Caller (``qwashed.cli``) provides the ``subparsers`` object returned
    by ``argparse.ArgumentParser.add_subparsers``.
    """
    audit_parser = subparsers.add_parser(
        "audit",
        help="HNDL auditor: scan endpoints and produce a signed migration roadmap",
        description=(
            "Probe TLS / SSH endpoints, classify their cryptographic posture, "
            "score exposure under a civil-society threat profile, and produce "
            "a signed migration roadmap."
        ),
    )
    audit_subs = audit_parser.add_subparsers(
        dest="audit_command",
        metavar="{run,profiles}",
        required=False,  # we manually print help if missing, for nicer UX
    )

    # `qwashed audit run`
    run_parser = audit_subs.add_parser(
        "run",
        help="run an audit using the given config file",
        description=(
            "Probe each target listed in the audit config, classify the "
            "negotiated cryptographic posture, score under a threat profile, "
            "and emit a signed JSON report. HTML and PDF renders are optional."
        ),
    )
    run_parser.add_argument(
        "config",
        help="path to an audit config YAML file (must define a 'targets' list)",
    )
    run_parser.add_argument(
        "--profile",
        default="default",
        help="built-in threat profile name (default: 'default')",
    )
    run_parser.add_argument(
        "--profile-file",
        default=None,
        help="path to a custom threat profile YAML (overrides --profile)",
    )
    run_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="path for the signed JSON report (default: stdout)",
    )
    run_parser.add_argument(
        "--html",
        default=None,
        help="optional path for an HTML render of the report",
    )
    run_parser.add_argument(
        "--pdf",
        default=None,
        help="optional path for a PDF render (requires qwashed[report] extra)",
    )
    run_parser.add_argument(
        "--signing-key",
        default=None,
        help=(
            "path to an Ed25519 signing key (32 raw bytes or base64). "
            "If omitted, a fresh ephemeral key is generated; in "
            "--deterministic mode an all-zero test seed is used."
        ),
    )
    run_parser.add_argument(
        "--deterministic",
        action="store_true",
        help=(
            "freeze timestamp, version string, and signing key seed so "
            "the JSON output is bit-identical across runs (test only)"
        ),
    )
    run_parser.add_argument(
        "--probe",
        choices=("native", "stdlib", "sslyze"),
        default="native",
        help=(
            "TLS probe implementation: 'native' (default; full PQ posture, "
            "no extras required), 'stdlib' (no KEX / no signature visibility), "
            "or 'sslyze' (requires the [audit-deep] extra)"
        ),
    )
    run_parser.add_argument(
        "--probe-timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=(f"per-target probe timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS})"),
    )
    run_parser.set_defaults(func=_audit_run)

    # `qwashed audit profiles`
    profiles_parser = audit_subs.add_parser(
        "profiles",
        help="list bundled threat profiles",
        description="List the threat profiles bundled with this Qwashed install.",
    )
    profiles_parser.set_defaults(func=_audit_profiles)

    # If the user runs `qwashed audit` with no subcommand, print help.
    def _audit_help(args: argparse.Namespace) -> int:
        del args
        audit_parser.print_help(sys.stderr)
        return 2

    audit_parser.set_defaults(func=_audit_help)


def run_audit_subcommand(args: argparse.Namespace) -> int:
    """Top-level dispatch entry; ``qwashed.cli`` wires this in."""
    func = getattr(args, "func", None)
    if func is None:  # pragma: no cover - argparse always sets one
        sys.stderr.write("qwashed audit: no handler bound\n")
        return 2
    return int(func(args))
