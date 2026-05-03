# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Load and validate Qwashed threat profiles from YAML.

Profiles ship in ``qwashed/audit/profiles/`` as YAML files. The loader
validates each one through :class:`qwashed.audit.schemas.ThreatProfile`
so a malformed profile is rejected at startup rather than silently
producing wrong scores at runtime.

Use ``yaml.safe_load`` only (never ``yaml.load``); we never execute YAML
tags. The dependency comes from ``[audit]`` extras (PyYAML).
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

from qwashed.audit.schemas import ThreatProfile
from qwashed.core.errors import ConfigurationError, SchemaValidationError
from qwashed.core.schemas import parse_strict

__all__ = [
    "available_profiles",
    "load_profile",
    "load_profile_from_path",
]


def _yaml_safe_load(text: str) -> Any:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - depends on env
        raise ConfigurationError(
            "PyYAML is required to load threat profiles; install qwashed[audit]",
            error_code="audit.missing_yaml",
        ) from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"YAML parse error: {exc}",
            error_code="audit.profile.bad_yaml",
        ) from exc


def load_profile(name: str) -> ThreatProfile:
    """Load a built-in profile by name (e.g. ``"default"``).

    Resolves to ``qwashed/audit/profiles/<name>.yaml``. Use
    :func:`load_profile_from_path` for user-supplied profiles outside the
    package.

    Raises
    ------
    ConfigurationError
        If the profile name does not exist or PyYAML is not installed.
    SchemaValidationError
        If the profile YAML parses but fails schema validation.
    """
    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise ConfigurationError(
            f"invalid profile name {name!r}; must be a simple identifier",
            error_code="audit.profile.bad_name",
        )
    try:
        traversable = resources.files("qwashed.audit.profiles") / f"{name}.yaml"
    except ModuleNotFoundError as exc:  # pragma: no cover - defensive
        raise ConfigurationError(
            f"profiles package missing: {exc}",
            error_code="audit.profile.missing_package",
        ) from exc
    if not traversable.is_file():
        raise ConfigurationError(
            f"unknown profile {name!r}; available: {sorted(available_profiles())}",
            error_code="audit.profile.unknown",
        )
    text = traversable.read_text(encoding="utf-8")
    data = _yaml_safe_load(text)
    if not isinstance(data, dict):
        raise SchemaValidationError(
            f"profile {name!r} must be a YAML mapping at the top level",
            error_code="audit.profile.not_mapping",
        )
    profile = parse_strict(ThreatProfile, data)
    assert isinstance(profile, ThreatProfile)
    return profile


def load_profile_from_path(path: str | Path) -> ThreatProfile:
    """Load a user-supplied threat profile from an arbitrary file path.

    Used by ``qwashed audit --profile-file <path>``. Same validation rules
    as :func:`load_profile`; the only difference is where the file comes
    from.
    """
    p = Path(path)
    if not p.is_file():
        raise ConfigurationError(
            f"profile file not found: {p}",
            error_code="audit.profile.file_missing",
        )
    text = p.read_text(encoding="utf-8")
    data = _yaml_safe_load(text)
    if not isinstance(data, dict):
        raise SchemaValidationError(
            f"profile file {p} must be a YAML mapping at the top level",
            error_code="audit.profile.not_mapping",
        )
    profile = parse_strict(ThreatProfile, data)
    assert isinstance(profile, ThreatProfile)
    return profile


def available_profiles() -> list[str]:
    """Return the names of all built-in profiles (sorted, no extension).

    Quietly returns ``[]`` if the profiles directory is missing; the caller
    will see ``audit.profile.unknown`` when they try to load anything.
    """
    try:
        package_root = resources.files("qwashed.audit.profiles")
    except ModuleNotFoundError:  # pragma: no cover - defensive
        return []
    names = []
    for entry in package_root.iterdir():
        if entry.is_file() and entry.name.endswith(".yaml"):
            names.append(entry.name.removesuffix(".yaml"))
    return sorted(names)
