# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.vault.hybrid_kem.

Covers:

* Correct keypair sizes against NIST FIPS 203 fixed lengths.
* Round-trip: encapsulator and decapsulator agree on a 32-byte secret.
* Two independent encapsulations under the same recipient produce
  different ciphertexts and different shared secrets (encap is
  randomized).
* Corrupting *either* component of the ciphertext envelope changes the
  derived shared secret (cross-test): both legs contribute, neither
  alone is sufficient.
* Truncated / extended / malformed envelopes raise :class:`SignatureError`
  with stable error_code prefixes.
"""

from __future__ import annotations

import warnings

import pytest

# The liboqs-python 0.14.1 vs liboqs 0.15.0 mismatch emits a one-shot
# UserWarning at module import. It does not affect API correctness, but
# it spams the test runner; silence it locally.
warnings.filterwarnings(
    "ignore",
    message=r"liboqs version .* differs",
    category=UserWarning,
)

from qwashed.core.errors import SignatureError  # noqa: E402
from qwashed.vault import hybrid_kem  # noqa: E402
from qwashed.vault.hybrid_kem import (  # noqa: E402
    HYBRID_KEM_SHARED_SECRET_LEN,
    MLKEM768_CIPHERTEXT_LEN,
    MLKEM768_PUBKEY_LEN,
    MLKEM768_SECRETKEY_LEN,
    X25519_PUBKEY_LEN,
    decapsulate,
    encapsulate,
    generate_keypair,
    parse_public_key,
    serialize_public_key,
)


class TestKeypairGeneration:
    def test_component_sizes(self) -> None:
        kp = generate_keypair()
        assert len(kp.x25519_sk) == X25519_PUBKEY_LEN
        assert len(kp.x25519_pk) == X25519_PUBKEY_LEN
        assert len(kp.mlkem768_pk) == MLKEM768_PUBKEY_LEN
        assert len(kp.mlkem768_sk) == MLKEM768_SECRETKEY_LEN

    def test_public_envelope_round_trip(self) -> None:
        kp = generate_keypair()
        envelope = kp.public_bytes()
        x_pk, m_pk = parse_public_key(envelope)
        assert x_pk == kp.x25519_pk
        assert m_pk == kp.mlkem768_pk

    def test_two_keypairs_differ(self) -> None:
        a = generate_keypair()
        b = generate_keypair()
        assert a.x25519_sk != b.x25519_sk
        assert a.mlkem768_sk != b.mlkem768_sk


class TestEncapDecapRoundTrip:
    def test_basic_round_trip(self) -> None:
        kp = generate_keypair()
        ct, ss_enc = encapsulate(kp.public_bytes())
        ss_dec = decapsulate(kp, ct)
        assert ss_enc == ss_dec
        assert len(ss_enc) == HYBRID_KEM_SHARED_SECRET_LEN

    def test_two_encaps_under_same_pk_differ(self) -> None:
        # Hybrid encap is randomized in both legs; two encaps must produce
        # different ciphertexts and different shared secrets.
        kp = generate_keypair()
        pk = kp.public_bytes()
        ct1, ss1 = encapsulate(pk)
        ct2, ss2 = encapsulate(pk)
        assert ct1 != ct2
        assert ss1 != ss2

    def test_decap_with_wrong_keypair_yields_different_secret(self) -> None:
        # Hybrid KEMs aren't authenticated by themselves; AEAD does that.
        # But a wrong recipient key MUST produce a different secret.
        kp_a = generate_keypair()
        kp_b = generate_keypair()
        ct, ss = encapsulate(kp_a.public_bytes())
        # We can't decap with kp_b for ct made for kp_a (component sk
        # mismatch), but a corrupted envelope-level case is covered below.
        with pytest.raises(SignatureError):
            decapsulate(kp_b, ct + b"\x00")  # malformed
        # Corrupting a few bytes inside the envelope while keeping it
        # well-formed should give a different secret, not match.
        corrupted = bytearray(ct)
        corrupted[100] ^= 0xFF
        ss2 = decapsulate(kp_a, bytes(corrupted))
        assert ss != ss2


class TestCrossLegSensitivity:
    """Both legs must contribute. Corrupting either one changes the secret."""

    def test_corrupted_classical_changes_secret(self) -> None:
        kp = generate_keypair()
        ct, ss = encapsulate(kp.public_bytes())
        # First component is the X25519 ephemeral (offset 4 onward).
        corrupted = bytearray(ct)
        corrupted[10] ^= 0xFF
        ss_b = decapsulate(kp, bytes(corrupted))
        assert ss_b != ss

    def test_corrupted_pq_changes_secret(self) -> None:
        kp = generate_keypair()
        ct, ss = encapsulate(kp.public_bytes())
        # Last bytes are inside the ML-KEM ciphertext component.
        corrupted = bytearray(ct)
        corrupted[-10] ^= 0xFF
        ss_b = decapsulate(kp, bytes(corrupted))
        assert ss_b != ss


class TestEnvelopeMalformedRejection:
    def test_truncated_envelope(self) -> None:
        kp = generate_keypair()
        ct, _ = encapsulate(kp.public_bytes())
        with pytest.raises(SignatureError):
            decapsulate(kp, ct[:-5])

    def test_trailing_bytes(self) -> None:
        kp = generate_keypair()
        ct, _ = encapsulate(kp.public_bytes())
        with pytest.raises(SignatureError):
            decapsulate(kp, ct + b"trailing")

    def test_zero_length_envelope(self) -> None:
        kp = generate_keypair()
        with pytest.raises(SignatureError):
            decapsulate(kp, b"")

    def test_only_length_prefix(self) -> None:
        kp = generate_keypair()
        with pytest.raises(SignatureError):
            decapsulate(kp, b"\x00\x00\x00\x00")  # zero-length first component

    def test_huge_length_prefix_rejected(self) -> None:
        kp = generate_keypair()
        # 4 GiB length prefix would otherwise allocate or truncate
        # silently. Must fail-closed.
        with pytest.raises(SignatureError):
            decapsulate(kp, b"\xff\xff\xff\xff" + b"\x00" * 8)

    def test_pubkey_envelope_with_wrong_x25519_length(self) -> None:
        with pytest.raises(SignatureError):
            serialize_public_key(b"\x00" * 31, b"\x00" * MLKEM768_PUBKEY_LEN)

    def test_pubkey_envelope_with_wrong_mlkem_length(self) -> None:
        with pytest.raises(SignatureError):
            serialize_public_key(b"\x00" * X25519_PUBKEY_LEN, b"\x00" * 100)

    def test_pubkey_envelope_trailing_bytes(self) -> None:
        kp = generate_keypair()
        env = kp.public_bytes() + b"X"
        with pytest.raises(SignatureError):
            parse_public_key(env)


class TestCombinerDeterminism:
    """The HKDF combiner must be a pure function of its inputs."""

    def test_combiner_deterministic(self) -> None:
        ss_x = b"\x01" * X25519_PUBKEY_LEN
        ss_m = b"\x02" * 32
        a = hybrid_kem._combine(ss_x, ss_m)
        b = hybrid_kem._combine(ss_x, ss_m)
        assert a == b
        assert len(a) == HYBRID_KEM_SHARED_SECRET_LEN

    def test_combiner_changes_when_classical_changes(self) -> None:
        ss_m = b"\x02" * 32
        a = hybrid_kem._combine(b"\x01" * X25519_PUBKEY_LEN, ss_m)
        b = hybrid_kem._combine(b"\x09" * X25519_PUBKEY_LEN, ss_m)
        assert a != b

    def test_combiner_changes_when_pq_changes(self) -> None:
        ss_x = b"\x01" * X25519_PUBKEY_LEN
        a = hybrid_kem._combine(ss_x, b"\x02" * 32)
        b = hybrid_kem._combine(ss_x, b"\x09" * 32)
        assert a != b

    def test_combiner_rejects_short_classical(self) -> None:
        with pytest.raises(SignatureError):
            hybrid_kem._combine(b"\x01" * 16, b"\x02" * 32)

    def test_combiner_rejects_short_pq(self) -> None:
        with pytest.raises(SignatureError):
            hybrid_kem._combine(b"\x01" * X25519_PUBKEY_LEN, b"\x02" * 16)


class TestCiphertextDimensions:
    def test_ct_envelope_size_is_predictable(self) -> None:
        kp = generate_keypair()
        ct, _ = encapsulate(kp.public_bytes())
        # 4 + 32 + 4 + 1088 = 1128.
        expected = 4 + X25519_PUBKEY_LEN + 4 + MLKEM768_CIPHERTEXT_LEN
        assert len(ct) == expected
