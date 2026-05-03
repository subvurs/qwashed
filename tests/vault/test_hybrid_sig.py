# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.vault.hybrid_sig.

Covers:

* Component sizes against NIST FIPS 204 fixed lengths.
* Round-trip sign / verify for matching pubkey + signature.
* AND-verify discipline: corrupting *either* leg of the signature
  (Ed25519 or ML-DSA-65) makes verification return ``False`` while
  leaving structural validity intact.
* Wrong-key rejection (signing keypair A, verifying with B's pubkey).
* Tampering the message after signing rejects.
* Truncated / extended envelopes raise structurally.
"""

from __future__ import annotations

import warnings

import pytest

warnings.filterwarnings(
    "ignore",
    message=r"liboqs version .* differs",
    category=UserWarning,
)

from qwashed.core.errors import SignatureError  # noqa: E402
from qwashed.vault.hybrid_sig import (  # noqa: E402
    ED25519_PUBKEY_LEN,
    ED25519_SIGNATURE_LEN,
    MLDSA65_PUBKEY_LEN,
    MLDSA65_SECRETKEY_LEN,
    MLDSA65_SIGNATURE_LEN,
    generate_keypair,
    parse_public_key,
    serialize_public_key,
    sign,
    verify,
)


class TestKeypairGeneration:
    def test_component_sizes(self) -> None:
        kp = generate_keypair()
        assert len(kp.ed25519_sk) == ED25519_PUBKEY_LEN
        assert len(kp.ed25519_pk) == ED25519_PUBKEY_LEN
        assert len(kp.mldsa65_pk) == MLDSA65_PUBKEY_LEN
        assert len(kp.mldsa65_sk) == MLDSA65_SECRETKEY_LEN

    def test_pubkey_round_trip(self) -> None:
        kp = generate_keypair()
        env = kp.public_bytes()
        ed_pk, m_pk = parse_public_key(env)
        assert ed_pk == kp.ed25519_pk
        assert m_pk == kp.mldsa65_pk


class TestSignVerifyRoundTrip:
    def test_basic_round_trip(self) -> None:
        kp = generate_keypair()
        msg = b"qwashed phase 3 hybrid signing test"
        sig = sign(kp, msg)
        # 4 + 64 + 4 + 3309 = 3381.
        assert len(sig) == 4 + ED25519_SIGNATURE_LEN + 4 + MLDSA65_SIGNATURE_LEN
        assert verify(kp.public_bytes(), msg, sig) is True

    def test_two_signatures_under_same_key_differ(self) -> None:
        # ML-DSA is randomized; two signatures over the same message
        # must differ at the byte level.
        kp = generate_keypair()
        msg = b"hello"
        sig1 = sign(kp, msg)
        sig2 = sign(kp, msg)
        assert sig1 != sig2
        assert verify(kp.public_bytes(), msg, sig1) is True
        assert verify(kp.public_bytes(), msg, sig2) is True

    def test_verify_with_other_keypair_fails(self) -> None:
        kp_a = generate_keypair()
        kp_b = generate_keypair()
        msg = b"belongs to A"
        sig = sign(kp_a, msg)
        assert verify(kp_b.public_bytes(), msg, sig) is False

    def test_verify_after_message_tamper_fails(self) -> None:
        kp = generate_keypair()
        msg = b"original"
        sig = sign(kp, msg)
        assert verify(kp.public_bytes(), b"tampered", sig) is False


class TestAndVerifyDiscipline:
    """Both component signatures must verify."""

    def test_corrupt_classical_fails_verify(self) -> None:
        kp = generate_keypair()
        msg = b"and-verify test"
        sig = bytearray(sign(kp, msg))
        # Flip a bit inside the Ed25519 signature body (after the 4-byte
        # length prefix).
        sig[10] ^= 0x01
        # Ed25519 signature length is preserved (we only flipped one
        # byte), so this should not be a structural failure -- it should
        # be a clean False from AND-verify.
        assert verify(kp.public_bytes(), msg, bytes(sig)) is False

    def test_corrupt_pq_fails_verify(self) -> None:
        kp = generate_keypair()
        msg = b"and-verify test"
        sig = bytearray(sign(kp, msg))
        # Flip a byte inside the ML-DSA-65 signature body.
        sig[-10] ^= 0x01
        assert verify(kp.public_bytes(), msg, bytes(sig)) is False

    def test_swap_classical_with_other_keypairs_signature(self) -> None:
        kp_a = generate_keypair()
        kp_b = generate_keypair()
        msg = b"identity binding"
        sig_a = sign(kp_a, msg)
        sig_b = sign(kp_b, msg)
        # Splice A's classical leg with B's PQ leg -> hybrid verify must
        # fail under either pubkey because the two legs disagree.
        # Layout: [4][64=ed25519][4][3309=mldsa].
        ed_a = sig_a[: 4 + ED25519_SIGNATURE_LEN]
        m_b = sig_b[4 + ED25519_SIGNATURE_LEN :]
        spliced = ed_a + m_b
        assert verify(kp_a.public_bytes(), msg, spliced) is False
        assert verify(kp_b.public_bytes(), msg, spliced) is False


class TestEnvelopeMalformedRejection:
    def test_truncated_signature(self) -> None:
        kp = generate_keypair()
        sig = sign(kp, b"x")
        with pytest.raises(SignatureError):
            verify(kp.public_bytes(), b"x", sig[:-5])

    def test_trailing_bytes_in_signature(self) -> None:
        kp = generate_keypair()
        sig = sign(kp, b"x")
        with pytest.raises(SignatureError):
            verify(kp.public_bytes(), b"x", sig + b"junk")

    def test_zero_length_signature(self) -> None:
        kp = generate_keypair()
        with pytest.raises(SignatureError):
            verify(kp.public_bytes(), b"x", b"")

    def test_pubkey_envelope_with_wrong_ed25519_length(self) -> None:
        with pytest.raises(SignatureError):
            serialize_public_key(b"\x00" * 31, b"\x00" * MLDSA65_PUBKEY_LEN)

    def test_pubkey_envelope_with_wrong_mldsa_length(self) -> None:
        with pytest.raises(SignatureError):
            serialize_public_key(b"\x00" * ED25519_PUBKEY_LEN, b"\x00" * 100)

    def test_pubkey_envelope_trailing_bytes(self) -> None:
        kp = generate_keypair()
        with pytest.raises(SignatureError):
            parse_public_key(kp.public_bytes() + b"X")
