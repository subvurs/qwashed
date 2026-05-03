# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Top-level Qwashed command-line interface.

Dispatch skeleton plus a working ``verify`` subcommand that uses
:mod:`qwashed.core.canonical` and :mod:`qwashed.core.signing` only.
``audit`` and ``vault`` subcommands are wired in from
:mod:`qwashed.audit.cli` (Phase 2) and :mod:`qwashed.vault.cli`
(Phase 3) respectively.

Usage::

    qwashed --version
    qwashed verify <artifact.json>
    qwashed audit run <config.yaml>
    qwashed vault {init|put|get|list|verify|export|recipients}
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from qwashed import __version__

# ---------------------------------------------------------------------------
# verify -- Phase 1 working subcommand
# ---------------------------------------------------------------------------


def _verify(args: argparse.Namespace) -> int:
    """Verify an Ed25519 signature embedded in a Qwashed signed artifact.

    The artifact format is JSON with:

      - top-level field ``signature_ed25519`` (base64 of the 64-byte sig)
      - top-level field ``ed25519_pubkey`` (base64 of the 32-byte pubkey)
      - all other fields canonicalized per RFC 8785 with the signature and
        pubkey fields removed before hashing.

    This minimal envelope is what every Qwashed-signed artifact follows,
    so ``qwashed verify`` works on audit reports, vault audit-log lines,
    and vault entry metadata uniformly.
    """
    import base64
    import json
    from pathlib import Path

    from qwashed.core.canonical import canonicalize
    from qwashed.core.errors import QwashedError
    from qwashed.core.signing import VerifyKey

    artifact_path = Path(args.artifact)
    try:
        raw = artifact_path.read_bytes()
    except OSError as exc:
        sys.stderr.write(f"qwashed verify: cannot read {artifact_path}: {exc}\n")
        return 2

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"qwashed verify: invalid JSON in {artifact_path}: {exc}\n")
        return 2

    if not isinstance(doc, dict):
        sys.stderr.write(
            f"qwashed verify: top-level JSON must be an object, got {type(doc).__name__}\n",
        )
        return 2

    sig_b64 = doc.get("signature_ed25519")
    pub_b64 = doc.get("ed25519_pubkey")
    if not isinstance(sig_b64, str) or not isinstance(pub_b64, str):
        sys.stderr.write(
            "qwashed verify: artifact missing required fields "
            "'signature_ed25519' and 'ed25519_pubkey'\n",
        )
        return 2

    try:
        signature = base64.b64decode(sig_b64, validate=True)
        verify_key = VerifyKey.from_b64(pub_b64)
    except (ValueError, QwashedError) as exc:
        sys.stderr.write(f"qwashed verify: malformed key or signature: {exc}\n")
        return 2

    # Canonicalize the artifact with the signature + pubkey fields stripped,
    # since those are what a sealed-artifact signature covers.
    payload_doc = {k: v for k, v in doc.items() if k not in {"signature_ed25519"}}
    try:
        payload = canonicalize(payload_doc)
    except QwashedError as exc:
        sys.stderr.write(f"qwashed verify: canonicalization failed: {exc}\n")
        return 2

    try:
        ok = verify_key.verify(payload, signature)
    except QwashedError as exc:
        sys.stderr.write(f"qwashed verify: structural verify error: {exc}\n")
        return 2

    if ok:
        sys.stdout.write(f"qwashed verify: OK ({artifact_path})\n")
        return 0

    sys.stderr.write(f"qwashed verify: SIGNATURE MISMATCH ({artifact_path})\n")
    return 1


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qwashed",
        description=(
            "Qwashed: free post-quantum hygiene for civil society. "
            "Quash quantum threats. Keep your data clean."
        ),
        epilog=(
            "Documentation: see README.md, QWASHED_BUILD_PLAN.txt, and "
            "THREAT_MODEL.md at the repository root."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"qwashed {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="{audit,vault,verify}",
        help="subcommand to run",
    )

    # `qwashed verify` -- Phase 1 working signature verifier
    verify_parser = subparsers.add_parser(
        "verify",
        help="verify the Ed25519 signature on a Qwashed signed artifact",
        description=(
            "Verify the Ed25519 signature embedded in a Qwashed signed "
            "artifact. Works on any JSON file with top-level 'signature_ed25519' "
            "and 'ed25519_pubkey' fields (audit reports, vault metadata, etc). "
            "Exits 0 on valid signature, 1 on signature mismatch, 2 on any "
            "structural / I/O / parse error."
        ),
    )
    verify_parser.add_argument(
        "artifact",
        help="path to the JSON artifact to verify",
    )
    verify_parser.set_defaults(func=_verify)

    # `qwashed audit` -- HNDL auditor (Phase 2)
    from qwashed.audit.cli import build_audit_parser

    build_audit_parser(subparsers)

    # `qwashed vault` -- Hybrid PQ vault (Phase 3)
    from qwashed.vault.cli import build_vault_parser

    build_vault_parser(subparsers)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``qwashed`` console script.

    Returns a process exit code.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help(sys.stderr)
        return 1

    result = func(args)
    return int(result) if result is not None else 0


if __name__ == "__main__":
    raise SystemExit(main())
