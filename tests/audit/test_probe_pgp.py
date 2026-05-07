# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for :mod:`qwashed.audit.probe_pgp` (Qwashed v0.2 §3.2)."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from qwashed.audit.probe_pgp import (
    MAX_PGP_BYTES,
    PgpProbe,
    parse_primary_public_key,
)
from qwashed.audit.schemas import AuditTarget


# ---------------------------------------------------------------------------
# Fixture builders: hand-roll OpenPGP public-key packets so we can exercise
# every algorithm path without depending on gpg / pgpy / sequoia.
# ---------------------------------------------------------------------------


def _new_format_packet(tag: int, body: bytes) -> bytes:
    """Wrap ``body`` in a new-format OpenPGP packet header (RFC 4880 §4.2.2)."""
    first = 0x80 | 0x40 | (tag & 0x3F)
    n = len(body)
    if n < 192:
        return bytes([first, n]) + body
    if n < 8384:
        v = n - 192
        b1 = (v >> 8) + 192
        b2 = v & 0xFF
        return bytes([first, b1, b2]) + body
    return bytes([first, 0xFF]) + n.to_bytes(4, "big") + body


def _v4_packet_header(algo: int, created: int = 0x60000000) -> bytes:
    """v4 public-key packet body prefix: version | created (4) | algo (1)."""
    return bytes([4]) + created.to_bytes(4, "big") + bytes([algo])


def _mpi(value: int, declared_bits: int | None = None) -> bytes:
    """Encode an integer as an OpenPGP MPI.

    If ``declared_bits`` is set, override the bit-length field (lets tests
    check the bucketing logic with sub-power-of-two sizes).
    """
    if value == 0:
        bit_length = 0
    else:
        bit_length = value.bit_length()
    if declared_bits is not None:
        bit_length = declared_bits
    byte_length = (bit_length + 7) // 8
    return bit_length.to_bytes(2, "big") + value.to_bytes(byte_length, "big")


def _oid_prefixed(hex_oid: str) -> bytes:
    """RFC 6637 OID encoding: 1-byte length || DER content bytes."""
    body = bytes.fromhex(hex_oid)
    return bytes([len(body)]) + body


def _ascii_armor(binary: bytes) -> bytes:
    """Wrap ``binary`` in a minimal ASCII-armor PGP block."""
    b64 = base64.b64encode(binary).decode("ascii")
    chunks = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    body = "\n".join(chunks)
    armor = (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        "\n"
        f"{body}\n"
        "=AAAA\n"
        "-----END PGP PUBLIC KEY BLOCK-----\n"
    )
    return armor.encode("ascii")


def _build_rsa_2048_key() -> bytes:
    """Build a v4 RSA-2048 public-key packet (algorithm 1)."""
    n = 1 << 2047  # 2048-bit modulus
    e = 65537
    body = _v4_packet_header(algo=1) + _mpi(n) + _mpi(e)
    return _new_format_packet(tag=6, body=body)


def _build_rsa_4096_key() -> bytes:
    n = 1 << 4095
    e = 65537
    body = _v4_packet_header(algo=1) + _mpi(n) + _mpi(e)
    return _new_format_packet(tag=6, body=body)


def _build_rsa_1024_key() -> bytes:
    n = 1 << 1023
    e = 65537
    body = _v4_packet_header(algo=1) + _mpi(n) + _mpi(e)
    return _new_format_packet(tag=6, body=body)


def _build_dsa_2048_key() -> bytes:
    """Algorithm 17 (DSA), with a 2048-bit p MPI."""
    p_val = 1 << 2047
    q_val = 1 << 255
    g_val = 2
    y_val = 3
    body = (
        _v4_packet_header(algo=17)
        + _mpi(p_val)
        + _mpi(q_val)
        + _mpi(g_val)
        + _mpi(y_val)
    )
    return _new_format_packet(tag=6, body=body)


def _build_ed25519_native_key() -> bytes:
    """Algorithm 27 (RFC 9580 native Ed25519): no MPI, fixed 32-byte material."""
    body = _v4_packet_header(algo=27) + b"\xab" * 32
    return _new_format_packet(tag=6, body=body)


def _build_eddsa_legacy_curve25519_key() -> bytes:
    """Algorithm 22 (legacy EdDSA) with curve25519 OID -> reported as ed25519."""
    oid = _oid_prefixed("2b06010401da470f01")  # 1.3.6.1.4.1.11591.15.1
    body = _v4_packet_header(algo=22) + oid + _mpi(int.from_bytes(b"\x40" + b"\x01" * 32, "big"))
    return _new_format_packet(tag=6, body=body)


def _build_ecdsa_nistp256_key() -> bytes:
    """Algorithm 19 (ECDSA) with NIST P-256 OID."""
    oid = _oid_prefixed("2a8648ce3d030107")
    point = int.from_bytes(b"\x04" + b"\x02" * 64, "big")
    body = _v4_packet_header(algo=19) + oid + _mpi(point)
    return _new_format_packet(tag=6, body=body)


def _build_ecdh_curve25519_key() -> bytes:
    """Algorithm 18 (ECDH) with curve25519 OID."""
    oid = _oid_prefixed("2b060104019755010501")
    point = int.from_bytes(b"\x40" + b"\x03" * 32, "big")
    # ECDH packets carry a KDF parameter trailer after the point; the
    # parser only needs the OID, so a truncated body still classifies.
    body = _v4_packet_header(algo=18) + oid + _mpi(point)
    return _new_format_packet(tag=6, body=body)


def _build_unknown_algo_key() -> bytes:
    """Algorithm 99 (reserved) -> classifier returns 'unknown'."""
    body = _v4_packet_header(algo=99) + b"\x00" * 8
    return _new_format_packet(tag=6, body=body)


# ---------------------------------------------------------------------------
# parse_primary_public_key
# ---------------------------------------------------------------------------


def test_parse_rsa_2048_binary() -> None:
    info = parse_primary_public_key(_build_rsa_2048_key())
    assert info is not None
    assert info.algorithm_id == 1
    assert info.friendly_name == "rsa_2048"
    assert info.bit_length == 2048


def test_parse_rsa_4096_binary() -> None:
    info = parse_primary_public_key(_build_rsa_4096_key())
    assert info is not None
    assert info.friendly_name == "rsa_4096"


def test_parse_rsa_1024_classical() -> None:
    info = parse_primary_public_key(_build_rsa_1024_key())
    assert info is not None
    assert info.friendly_name == "rsa_1024"


def test_parse_dsa_2048() -> None:
    info = parse_primary_public_key(_build_dsa_2048_key())
    assert info is not None
    assert info.algorithm_id == 17
    assert info.friendly_name == "dsa_2048"


def test_parse_ed25519_native() -> None:
    info = parse_primary_public_key(_build_ed25519_native_key())
    assert info is not None
    assert info.algorithm_id == 27
    assert info.friendly_name == "ed25519"


def test_parse_eddsa_legacy_curve25519_reports_as_ed25519() -> None:
    info = parse_primary_public_key(_build_eddsa_legacy_curve25519_key())
    assert info is not None
    assert info.algorithm_id == 22
    assert info.friendly_name == "ed25519"


def test_parse_ecdsa_nistp256() -> None:
    info = parse_primary_public_key(_build_ecdsa_nistp256_key())
    assert info is not None
    assert info.algorithm_id == 19
    assert info.friendly_name == "ecdsa_nistp256"


def test_parse_ecdh_curve25519() -> None:
    info = parse_primary_public_key(_build_ecdh_curve25519_key())
    assert info is not None
    assert info.algorithm_id == 18
    assert info.friendly_name == "ecdh_curve25519"


def test_parse_unknown_algorithm_id() -> None:
    info = parse_primary_public_key(_build_unknown_algo_key())
    assert info is not None
    assert info.algorithm_id == 99
    # Empty friendly_name -> classifier downstream maps to "unknown".
    assert info.friendly_name == ""


def test_parse_ascii_armor_round_trip() -> None:
    binary = _build_rsa_2048_key()
    armored = _ascii_armor(binary)
    info = parse_primary_public_key(armored)
    assert info is not None
    assert info.friendly_name == "rsa_2048"


def test_parse_returns_none_on_garbage() -> None:
    assert parse_primary_public_key(b"this is not a pgp key file") is None


def test_parse_returns_none_on_empty() -> None:
    assert parse_primary_public_key(b"") is None


def test_parse_skips_subkey_to_find_primary() -> None:
    # Concatenate a Public-Subkey (tag 14) before the real Public-Key (tag 6);
    # parser must walk to the primary key.
    subkey_body = _v4_packet_header(algo=18) + _oid_prefixed("2b06010401da470f01")
    # Subkey packet tag = 14 with a small synthetic body.
    subkey_packet = _new_format_packet(tag=14, body=subkey_body)
    primary = _build_rsa_2048_key()
    info = parse_primary_public_key(subkey_packet + primary)
    assert info is not None
    assert info.friendly_name == "rsa_2048"


def test_parse_truncates_at_size_cap() -> None:
    # parse_primary_public_key truncates input to MAX_PGP_BYTES; verify a
    # huge garbage prefix cannot stall the parser.
    junk = b"\x00" * (MAX_PGP_BYTES + 1024)
    assert parse_primary_public_key(junk) is None


# ---------------------------------------------------------------------------
# PgpProbe end-to-end
# ---------------------------------------------------------------------------


@pytest.fixture()
def probe() -> PgpProbe:
    return PgpProbe()


def _write_key(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_probe_ok_rsa(tmp_path: Path, probe: PgpProbe) -> None:
    key_path = _write_key(tmp_path, "rsa.pgp", _build_rsa_2048_key())
    target = AuditTarget(
        host="alice@example.org",
        protocol="pgp",
        key_path=str(key_path),
    )
    result = probe.probe(target)
    assert result.status == "ok"
    assert result.signature_algorithm == "rsa_2048"
    assert result.extras["pgp_algorithm_id"] == "1"
    assert result.extras["pgp_bit_length"] == "2048"
    assert result.elapsed_seconds >= 0


def test_probe_ok_ed25519(tmp_path: Path, probe: PgpProbe) -> None:
    key_path = _write_key(tmp_path, "ed25519.pgp", _build_ed25519_native_key())
    target = AuditTarget(
        host="bob@example.org",
        protocol="pgp",
        key_path=str(key_path),
    )
    result = probe.probe(target)
    assert result.status == "ok"
    assert result.signature_algorithm == "ed25519"
    assert "pgp_bit_length" not in result.extras  # no MPI for native curves


def test_probe_ascii_armor(tmp_path: Path, probe: PgpProbe) -> None:
    key_path = _write_key(
        tmp_path,
        "armored.asc",
        _ascii_armor(_build_rsa_2048_key()),
    )
    target = AuditTarget(
        host="alice@example.org",
        protocol="pgp",
        key_path=str(key_path),
    )
    result = probe.probe(target)
    assert result.status == "ok"
    assert result.signature_algorithm == "rsa_2048"


def test_probe_unreachable_when_file_missing(tmp_path: Path, probe: PgpProbe) -> None:
    target = AuditTarget(
        host="alice@example.org",
        protocol="pgp",
        key_path=str(tmp_path / "does-not-exist.pgp"),
    )
    result = probe.probe(target)
    assert result.status == "unreachable"
    assert "cannot read pgp key" in result.error_detail


def test_probe_malformed_when_empty(tmp_path: Path, probe: PgpProbe) -> None:
    key_path = _write_key(tmp_path, "empty.pgp", b"")
    target = AuditTarget(
        host="alice@example.org",
        protocol="pgp",
        key_path=str(key_path),
    )
    result = probe.probe(target)
    assert result.status == "malformed"
    assert "empty" in result.error_detail


def test_probe_malformed_when_garbage(tmp_path: Path, probe: PgpProbe) -> None:
    key_path = _write_key(tmp_path, "garbage.pgp", b"definitely not a pgp key")
    target = AuditTarget(
        host="alice@example.org",
        protocol="pgp",
        key_path=str(key_path),
    )
    result = probe.probe(target)
    assert result.status == "malformed"


def test_probe_malformed_when_oversize(tmp_path: Path, probe: PgpProbe) -> None:
    huge = b"\x00" * (MAX_PGP_BYTES + 16)
    key_path = _write_key(tmp_path, "huge.pgp", huge)
    target = AuditTarget(
        host="alice@example.org",
        protocol="pgp",
        key_path=str(key_path),
    )
    result = probe.probe(target)
    assert result.status == "malformed"
    assert "exceeds" in result.error_detail


def test_probe_rejects_wrong_protocol(probe: PgpProbe) -> None:
    target = AuditTarget(host="example.org", port=443, protocol="tls")
    result = probe.probe(target)
    assert result.status == "malformed"
    assert "PgpProbe" in result.error_detail


def test_probe_never_raises_on_truncated_packet(
    tmp_path: Path,
    probe: PgpProbe,
) -> None:
    # First byte claims a new-format Public-Key packet of a long length,
    # but no body follows. Parser must return None / probe must return
    # 'malformed' rather than IndexError-out.
    truncated = bytes([0x80 | 0x40 | 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    key_path = _write_key(tmp_path, "truncated.pgp", truncated)
    target = AuditTarget(
        host="alice@example.org",
        protocol="pgp",
        key_path=str(key_path),
    )
    result = probe.probe(target)
    assert result.status == "malformed"
