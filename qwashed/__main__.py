# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Allow ``python -m qwashed`` to invoke the CLI."""

from __future__ import annotations

from qwashed.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
