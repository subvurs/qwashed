# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Phase 0 smoke tests.

These tests verify only that the package was installed correctly and that
the top-level surface is wired up. They do NOT exercise any cryptographic
behavior; that arrives in Phase 1+ tests.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from importlib import metadata

import pytest

# ---------------------------------------------------------------------------
# Package surface
# ---------------------------------------------------------------------------


def test_package_imports() -> None:
    """`import qwashed` must succeed and expose version metadata."""
    import qwashed

    assert qwashed.__version__
    assert qwashed.__license__ == "Apache-2.0"
    assert qwashed.__author__


def test_version_matches_pyproject() -> None:
    """The runtime version must match the version installed by the build backend.

    Catches the common bug where ``__version__`` drifts from ``pyproject.toml``
    after a release bump.
    """
    import qwashed

    installed_version = metadata.version("qwashed")
    assert qwashed.__version__ == installed_version


def test_subpackages_import() -> None:
    """All declared subpackages must import without side effects."""
    import qwashed.audit
    import qwashed.core
    import qwashed.vault

    # Reference the imports so that linters do not flag them as unused.
    assert qwashed.audit is not None
    assert qwashed.core is not None
    assert qwashed.vault is not None


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_main_callable() -> None:
    """`qwashed.cli.main` must be importable and callable."""
    from qwashed.cli import main

    assert callable(main)


def test_cli_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """`qwashed --version` must print a version string and exit cleanly."""
    from qwashed.cli import main

    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])

    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert re.search(r"qwashed\s+\d+\.\d+\.\d+", output)


def test_cli_no_args_prints_help_and_returns_nonzero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Bare `qwashed` must print help and return a nonzero exit code.

    This nudges the user toward `--help` or a subcommand without producing
    a misleading "success" exit status.
    """
    from qwashed.cli import main

    rc = main([])
    captured = capsys.readouterr()

    assert rc != 0
    assert "qwashed" in captured.err.lower() or "qwashed" in captured.out.lower()


def test_cli_audit_no_subcommand_prints_help(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`qwashed audit` with no subcommand prints help and exits non-zero."""
    from qwashed.cli import main

    rc = main(["audit"])
    captured = capsys.readouterr()

    assert rc == 2
    err = captured.err.lower()
    assert "usage" in err
    assert "run" in err
    assert "profiles" in err


def test_cli_vault_no_subcommand_prints_help(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`qwashed vault` with no subcommand prints help and exits non-zero."""
    from qwashed.cli import main

    rc = main(["vault"])
    captured = capsys.readouterr()

    assert rc == 2
    err = captured.err.lower()
    assert "usage" in err
    assert "init" in err
    assert "put" in err
    assert "get" in err
    assert "verify" in err
    assert "export" in err


# ---------------------------------------------------------------------------
# Console script entry point (only meaningful after `pip install -e .`)
# ---------------------------------------------------------------------------


def test_console_script_installed() -> None:
    """`qwashed --version` invoked as a console script must work after install.

    Skipped if the user is running tests without having installed the package
    (e.g., pure `pytest` from a fresh checkout without `pip install -e .`).
    """
    qwashed_path = shutil.which("qwashed")
    if qwashed_path is None:
        pytest.skip("qwashed console script not on PATH; run `pip install -e .` first")

    # qwashed_path is the absolute path returned by shutil.which() above;
    # it is not user input. The S603 lint is a structural false-positive here.
    result = subprocess.run(
        [qwashed_path, "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, (
        f"qwashed --version failed: rc={result.returncode}, "
        f"stdout={result.stdout!r}, stderr={result.stderr!r}"
    )
    assert "qwashed" in (result.stdout + result.stderr).lower()


def test_python_dash_m_invocation() -> None:
    """`python -m qwashed --version` must also work (via __main__.py)."""
    result = subprocess.run(
        [sys.executable, "-m", "qwashed", "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert "qwashed" in (result.stdout + result.stderr).lower()
