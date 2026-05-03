# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.core.signing."""

from __future__ import annotations

import base64

import pytest

from qwashed.core.errors import SignatureError
from qwashed.core.signing import (
    ED25519_PUBKEY_LEN,
    ED25519_SIGNATURE_LEN,
    SigningKey,
    VerifyKey,
)


class TestRoundTrip:
    def test_sign_and_verify_succeeds(self) -> None:
        sk = SigningKey.generate()
        sig = sk.sign(b"message")
        assert len(sig) == ED25519_SIGNATURE_LEN
        assert sk.verify_key.verify(b"message", sig) is True

    def test_verify_fails_on_modified_message(self) -> None:
        sk = SigningKey.generate()
        sig = sk.sign(b"original")
        assert sk.verify_key.verify(b"tampered", sig) is False

    def test_verify_fails_on_modified_signature(self) -> None:
        sk = SigningKey.generate()
        sig = bytearray(sk.sign(b"msg"))
        sig[0] ^= 0xFF
        assert sk.verify_key.verify(b"msg", bytes(sig)) is False


class TestSerialization:
    def test_pubkey_roundtrip_bytes(self) -> None:
        sk = SigningKey.generate()
        pk_bytes = sk.verify_key.to_bytes()
        assert len(pk_bytes) == ED25519_PUBKEY_LEN

        roundtripped = VerifyKey.from_bytes(pk_bytes)
        assert roundtripped == sk.verify_key

    def test_pubkey_roundtrip_b64(self) -> None:
        sk = SigningKey.generate()
        pk_b64 = sk.verify_key.to_b64()
        roundtripped = VerifyKey.from_b64(pk_b64)
        assert roundtripped == sk.verify_key

    def test_seed_roundtrip(self) -> None:
        sk1 = SigningKey.generate()
        seed = sk1.to_bytes()
        assert len(seed) == 32

        sk2 = SigningKey.from_bytes(seed)
        # Same seed produces same verify key.
        assert sk1.verify_key == sk2.verify_key
        # And same signature on a fixed message (Ed25519 is deterministic).
        assert sk1.sign(b"x") == sk2.sign(b"x")


class TestStructuralErrors:
    def test_pubkey_wrong_length(self) -> None:
        with pytest.raises(SignatureError) as exc:
            VerifyKey.from_bytes(b"\x00" * 16)
        assert exc.value.error_code == "signing.bad_pubkey_length"

    def test_pubkey_bad_b64(self) -> None:
        with pytest.raises(SignatureError) as exc:
            VerifyKey.from_b64("@@@notb64@@@")
        assert exc.value.error_code == "signing.bad_pubkey_b64"

    def test_seed_wrong_length(self) -> None:
        with pytest.raises(SignatureError) as exc:
            SigningKey.from_bytes(b"\x00" * 16)
        assert exc.value.error_code == "signing.bad_seed_length"

    def test_signature_wrong_length(self) -> None:
        sk = SigningKey.generate()
        with pytest.raises(SignatureError) as exc:
            sk.verify_key.verify(b"msg", b"too short")
        assert exc.value.error_code == "signing.bad_signature_length"


class TestEqualityAndRepr:
    def test_verify_key_equality(self) -> None:
        sk = SigningKey.generate()
        a = sk.verify_key
        b = VerifyKey.from_bytes(a.to_bytes())
        assert a == b
        assert hash(a) == hash(b)

    def test_verify_key_inequality(self) -> None:
        a = SigningKey.generate().verify_key
        b = SigningKey.generate().verify_key
        assert a != b

    def test_verify_key_compares_only_to_verify_key(self) -> None:
        a = SigningKey.generate().verify_key
        assert (a == "string") is False
        assert (a == 42) is False

    def test_signing_key_repr_does_not_leak_seed(self) -> None:
        sk = SigningKey.generate()
        seed = sk.to_bytes()
        seed_b64 = base64.b64encode(seed).decode("ascii")
        rep = repr(sk)
        # Repr must not contain the seed bytes in any obvious encoding.
        assert seed.hex() not in rep
        assert seed_b64 not in rep

    def test_verify_key_repr_truncated(self) -> None:
        vk = SigningKey.generate().verify_key
        rep = repr(vk)
        assert "VerifyKey(" in rep
        # Truncated to 8 chars + "...".
        full = vk.to_b64()
        assert full not in rep
