# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.core.kdf."""

from __future__ import annotations

import os

import pytest

from qwashed.core.errors import KeyDerivationError
from qwashed.core.kdf import (
    HKDF_SHA256_MAX_OUTPUT,
    hkdf_sha256,
    info_for,
)


class TestHkdfSha256:
    def test_basic_derivation(self) -> None:
        out = hkdf_sha256(
            ikm=b"input-keying-material",
            salt=b"salt",
            info=b"qwashed/test/v0.1/example",
            length=32,
        )
        assert len(out) == 32

    def test_deterministic(self) -> None:
        a = hkdf_sha256(ikm=b"ikm", salt=b"salt", info=b"info", length=32)
        b = hkdf_sha256(ikm=b"ikm", salt=b"salt", info=b"info", length=32)
        assert a == b

    def test_different_info_produces_different_output(self) -> None:
        a = hkdf_sha256(ikm=b"ikm", salt=b"salt", info=b"a", length=32)
        b = hkdf_sha256(ikm=b"ikm", salt=b"salt", info=b"b", length=32)
        assert a != b

    def test_empty_ikm_rejected(self) -> None:
        with pytest.raises(KeyDerivationError) as exc:
            hkdf_sha256(ikm=b"", salt=b"salt", info=b"info", length=32)
        assert exc.value.error_code == "kdf.hkdf.empty_ikm"

    def test_zero_length_rejected(self) -> None:
        with pytest.raises(KeyDerivationError) as exc:
            hkdf_sha256(ikm=b"ikm", salt=b"salt", info=b"info", length=0)
        assert exc.value.error_code == "kdf.hkdf.bad_length"

    def test_overlong_rejected(self) -> None:
        with pytest.raises(KeyDerivationError) as exc:
            hkdf_sha256(
                ikm=b"ikm",
                salt=b"salt",
                info=b"info",
                length=HKDF_SHA256_MAX_OUTPUT + 1,
            )
        assert exc.value.error_code == "kdf.hkdf.bad_length"

    def test_max_length_accepted(self) -> None:
        out = hkdf_sha256(
            ikm=b"ikm",
            salt=b"salt",
            info=b"info",
            length=HKDF_SHA256_MAX_OUTPUT,
        )
        assert len(out) == HKDF_SHA256_MAX_OUTPUT


class TestInfoFor:
    def test_canonical_format(self) -> None:
        assert info_for(module="vault", purpose="kem") == b"qwashed/vault/v0.1/kem"
        assert info_for(module="audit", purpose="sig") == b"qwashed/audit/v0.1/sig"

    def test_explicit_version(self) -> None:
        assert info_for(module="vault", purpose="kem", version="v0.2") == (
            b"qwashed/vault/v0.2/kem"
        )

    def test_empty_purpose_rejected(self) -> None:
        with pytest.raises(KeyDerivationError) as exc:
            info_for(module="vault", purpose="")
        assert exc.value.error_code == "kdf.info.empty_purpose"

    def test_slash_in_purpose_rejected(self) -> None:
        with pytest.raises(KeyDerivationError) as exc:
            info_for(module="vault", purpose="kem/forged")
        assert exc.value.error_code == "kdf.info.slash_in_purpose"


# Argon2id tests are gated on the optional [vault] extra. If argon2-cffi
# is not installed, the import-time check inside argon2id() raises
# KeyDerivationError("kdf.argon2.missing_dep"). We verify that fallback
# without forcing the vault extra to be installed.
class TestArgon2id:
    def test_either_runs_or_fails_closed_on_missing_dep(self) -> None:
        from qwashed.core.kdf import argon2id

        salt = os.urandom(16)
        try:
            result = argon2id(password=b"pw", salt=salt, length=32)
        except KeyDerivationError as exc:
            # If argon2-cffi is not installed, the error_code is fixed.
            assert exc.error_code == "kdf.argon2.missing_dep"
        else:
            assert len(result) == 32

    def test_short_salt_rejected(self) -> None:
        from qwashed.core.kdf import argon2id

        with pytest.raises(KeyDerivationError) as exc:
            argon2id(password=b"pw", salt=b"short", length=32)
        assert exc.value.error_code == "kdf.argon2.short_salt"

    def test_empty_password_rejected(self) -> None:
        from qwashed.core.kdf import argon2id

        with pytest.raises(KeyDerivationError) as exc:
            argon2id(password=b"", salt=os.urandom(16), length=32)
        assert exc.value.error_code == "kdf.argon2.empty_password"

    def test_weak_memory_rejected(self) -> None:
        from qwashed.core.kdf import argon2id

        with pytest.raises(KeyDerivationError) as exc:
            argon2id(
                password=b"pw",
                salt=os.urandom(16),
                memory_kib=1024,
                length=32,
            )
        assert exc.value.error_code == "kdf.argon2.weak_memory"

    def test_short_output_rejected(self) -> None:
        from qwashed.core.kdf import argon2id

        with pytest.raises(KeyDerivationError) as exc:
            argon2id(password=b"pw", salt=os.urandom(16), length=8)
        assert exc.value.error_code == "kdf.argon2.short_output"
