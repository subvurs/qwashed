# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.audit.profile_loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from qwashed.audit.profile_loader import (
    available_profiles,
    load_profile,
    load_profile_from_path,
)
from qwashed.audit.schemas import ThreatProfile
from qwashed.core.errors import ConfigurationError, SchemaValidationError


class TestAvailableProfiles:
    def test_lists_default(self) -> None:
        names = available_profiles()
        assert "default" in names
        assert "journalism" in names
        assert "healthcare" in names
        assert "legal" in names

    def test_sorted(self) -> None:
        names = available_profiles()
        assert names == sorted(names)


class TestLoadProfile:
    def test_default(self) -> None:
        prof = load_profile("default")
        assert isinstance(prof, ThreatProfile)
        assert prof.name == "default"
        assert prof.aggregation == "max"

    def test_journalism(self) -> None:
        prof = load_profile("journalism")
        assert prof.name == "journalism"
        # Journalism profile is strictly more severe than default.
        assert prof.category_weights["classical"] >= 0.95
        assert prof.archival_likelihood >= 0.9

    def test_healthcare(self) -> None:
        prof = load_profile("healthcare")
        assert prof.name == "healthcare"

    def test_legal(self) -> None:
        prof = load_profile("legal")
        assert prof.name == "legal"

    def test_unknown_profile(self) -> None:
        with pytest.raises(ConfigurationError) as exc:
            load_profile("nonexistent_profile_xyz")
        assert exc.value.error_code == "audit.profile.unknown"

    def test_path_traversal_blocked(self) -> None:
        with pytest.raises(ConfigurationError) as exc:
            load_profile("../etc/passwd")
        assert exc.value.error_code == "audit.profile.bad_name"

    def test_empty_name(self) -> None:
        with pytest.raises(ConfigurationError):
            load_profile("")

    def test_dotfile_name(self) -> None:
        with pytest.raises(ConfigurationError) as exc:
            load_profile(".hidden")
        assert exc.value.error_code == "audit.profile.bad_name"


class TestLoadProfileFromPath:
    def test_user_profile(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yaml"
        path.write_text(
            """
name: custom
description: a test profile from a user file
category_weights:
  classical: 0.7
  hybrid_pq: 0.2
  pq_only: 0.05
  unknown: 0.7
archival_likelihood: 0.5
severity_thresholds:
  info: 0.0
  low: 0.2
  moderate: 0.4
  high: 0.6
  critical: 0.8
aggregation: mean
""",
            encoding="utf-8",
        )
        prof = load_profile_from_path(path)
        assert prof.name == "custom"
        assert prof.aggregation == "mean"

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError) as exc:
            load_profile_from_path(tmp_path / "missing.yaml")
        assert exc.value.error_code == "audit.profile.file_missing"

    def test_not_mapping(self, tmp_path: Path) -> None:
        path = tmp_path / "list.yaml"
        path.write_text("- a\n- b\n", encoding="utf-8")
        with pytest.raises(SchemaValidationError) as exc:
            load_profile_from_path(path)
        assert exc.value.error_code == "audit.profile.not_mapping"

    def test_malformed_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text("name: [unterminated\n", encoding="utf-8")
        with pytest.raises(ConfigurationError) as exc:
            load_profile_from_path(path)
        assert exc.value.error_code == "audit.profile.bad_yaml"

    def test_validation_failure_propagates(self, tmp_path: Path) -> None:
        # weights non-monotonic: should raise SchemaValidationError.
        path = tmp_path / "broken.yaml"
        path.write_text(
            """
name: broken
description: weights wrong
category_weights:
  classical: 0.1
  hybrid_pq: 0.5
  pq_only: 0.05
  unknown: 0.5
archival_likelihood: 0.5
severity_thresholds:
  info: 0.0
  low: 0.2
  moderate: 0.4
  high: 0.6
  critical: 0.8
aggregation: max
""",
            encoding="utf-8",
        )
        with pytest.raises(SchemaValidationError):
            load_profile_from_path(path)
