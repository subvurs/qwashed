# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Internal TLS wire-format helpers for :class:`qwashed.audit.probe.NativeTlsProbe`.

This module is *internal*. Public surface is ``NativeTlsProbe`` in
:mod:`qwashed.audit.probe`; this module is implementation detail and
may change without notice. It exists only so the wire-handling code is
readable in isolation, not braided into the probe class.

Scope
-----
* TLS 1.3 (RFC 8446) and TLS 1.2 (RFC 5246) ClientHello assembly.
* ServerHello parsing (extensions: ``supported_versions``, ``key_share``).
* Handshake-message reassembly across record boundaries.
* TLS 1.3 key schedule: HKDF-Extract / HKDF-Expand-Label / Derive-Secret.
* AES-128-GCM and AES-256-GCM record protection (server -> client only).
* Certificate handshake parsing (first cert DER -> signature algorithm OID).
* TLS 1.2 cleartext Certificate parsing.
* TLS 1.2 ServerKeyExchange parsing for the negotiated named curve.

Not in scope
------------
* PSK / session resumption.
* HelloRetryRequest (we offer X25519 + secp256r1 + secp384r1 + X25519MLKEM768
  in supported_groups; modern servers will accept one of those without an HRR).
* Client certificates, CertificateVerify, Finished, sending alerts.
* Application data.
* TLS 1.0 / 1.1 / SSLv3 — explicitly rejected.

Design notes
------------
* No private bytes from the wire are ever logged by callers; this module
  raises :class:`TlsWireError` with a stable status string and a
  short summary message, never with the raw wire bytes.
* Bounded: every read is gated by a caller-provided byte budget so a
  malicious server cannot make us allocate unboundedly. The budget is
  enforced in the caller, not here.
* All multi-byte integers are big-endian per TLS convention.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import secrets
import socket
import struct
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

__all__ = [
    "CIPHER_NAMES",
    "GROUP_NAMES",
    "TLS13_CIPHER_PARAMS",
    "TLS_1_2",
    "TLS_1_3",
    "CertificateInfo",
    "ClientHelloMaterial",
    "HandshakeReader",
    "ServerHelloInfo",
    "TlsWireError",
    "build_client_hello",
    "cert_sig_algo_friendly_name",
    "decrypt_tls13_record",
    "derive_tls13_server_handshake_keys",
    "parse_certificate_message",
    "parse_server_hello",
    "parse_server_key_exchange_named_curve",
    "read_record",
]


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

# Record content types (RFC 8446 §B.1)
RECORD_CHANGE_CIPHER_SPEC: Final[int] = 20
RECORD_ALERT: Final[int] = 21
RECORD_HANDSHAKE: Final[int] = 22
RECORD_APPLICATION_DATA: Final[int] = 23

# Handshake message types (RFC 8446 §B.3)
HS_CLIENT_HELLO: Final[int] = 1
HS_SERVER_HELLO: Final[int] = 2
HS_NEW_SESSION_TICKET: Final[int] = 4
HS_ENCRYPTED_EXTENSIONS: Final[int] = 8
HS_CERTIFICATE: Final[int] = 11
HS_SERVER_KEY_EXCHANGE: Final[int] = 12  # TLS 1.2
HS_CERTIFICATE_REQUEST: Final[int] = 13
HS_SERVER_HELLO_DONE: Final[int] = 14  # TLS 1.2
HS_CERTIFICATE_VERIFY: Final[int] = 15
HS_FINISHED: Final[int] = 20

# Extension types (IANA TLS-ExtensionType + RFC 8446 §B.3.1)
EXT_SERVER_NAME: Final[int] = 0
EXT_SUPPORTED_GROUPS: Final[int] = 10
EXT_SIGNATURE_ALGORITHMS: Final[int] = 13
EXT_PSK_KEY_EXCHANGE_MODES: Final[int] = 45
EXT_SUPPORTED_VERSIONS: Final[int] = 43
EXT_KEY_SHARE: Final[int] = 51

# TLS protocol versions
TLS_1_3: Final[int] = 0x0304
TLS_1_2: Final[int] = 0x0303

# Named groups (RFC 8446 §4.2.7 + IANA + draft-kwiatkowski-tls-ecdhe-mlkem)
GROUP_X25519: Final[int] = 0x001D
GROUP_SECP256R1: Final[int] = 0x0017
GROUP_SECP384R1: Final[int] = 0x0018
GROUP_SECP521R1: Final[int] = 0x0019
GROUP_X25519MLKEM768: Final[int] = 0x11EC  # draft-kwiatkowski-tls-ecdhe-mlkem

GROUP_NAMES: Final[dict[int, str]] = {
    GROUP_X25519: "X25519",
    GROUP_SECP256R1: "secp256r1",
    GROUP_SECP384R1: "secp384r1",
    GROUP_SECP521R1: "secp521r1",
    GROUP_X25519MLKEM768: "X25519MLKEM768",
}

# Cipher suites
CIPHER_TLS13_AES_128_GCM_SHA256: Final[int] = 0x1301
CIPHER_TLS13_AES_256_GCM_SHA384: Final[int] = 0x1302

CIPHER_TLS12_ECDHE_RSA_AES128_GCM_SHA256: Final[int] = 0xC02F
CIPHER_TLS12_ECDHE_ECDSA_AES128_GCM_SHA256: Final[int] = 0xC02B
CIPHER_TLS12_ECDHE_RSA_AES256_GCM_SHA384: Final[int] = 0xC030
CIPHER_TLS12_ECDHE_ECDSA_AES256_GCM_SHA384: Final[int] = 0xC02C

CIPHER_NAMES: Final[dict[int, str]] = {
    CIPHER_TLS13_AES_128_GCM_SHA256: "TLS_AES_128_GCM_SHA256",
    CIPHER_TLS13_AES_256_GCM_SHA384: "TLS_AES_256_GCM_SHA384",
    CIPHER_TLS12_ECDHE_RSA_AES128_GCM_SHA256: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    CIPHER_TLS12_ECDHE_ECDSA_AES128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    CIPHER_TLS12_ECDHE_RSA_AES256_GCM_SHA384: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    CIPHER_TLS12_ECDHE_ECDSA_AES256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
}

#: TLS 1.3 cipher-suite parameters: hash class, hashlib name, key length (bytes).
#:
#: ``hashlib_name`` is stored explicitly because at class level
#: ``hashes.SHA256.name`` is a property descriptor, not a ``str`` — mypy
#: --strict complains, and runtime access on the class works only because
#: of an attribute alias inside the cryptography library. Pass the string
#: through the table to avoid the foot-gun.
TLS13_CIPHER_PARAMS: Final[dict[int, tuple[type[hashes.HashAlgorithm], str, int]]] = {
    CIPHER_TLS13_AES_128_GCM_SHA256: (hashes.SHA256, "sha256", 16),
    CIPHER_TLS13_AES_256_GCM_SHA384: (hashes.SHA384, "sha384", 32),
}

# Signature algorithms we offer in CH (RFC 8446 §4.2.3).
SIG_ALGOS_OFFERED: Final[list[int]] = [
    0x0807,  # ed25519
    0x0808,  # ed448
    0x0809,  # rsa_pss_pss_sha256
    0x080A,  # rsa_pss_pss_sha384
    0x0804,  # rsa_pss_rsae_sha256
    0x0805,  # rsa_pss_rsae_sha384
    0x0806,  # rsa_pss_rsae_sha512
    0x0403,  # ecdsa_secp256r1_sha256
    0x0503,  # ecdsa_secp384r1_sha384
    0x0603,  # ecdsa_secp521r1_sha512
    0x0401,  # rsa_pkcs1_sha256 (TLS 1.2 cert compat)
    0x0501,  # rsa_pkcs1_sha384
    0x0601,  # rsa_pkcs1_sha512
]

#: TLS 1.3 ServerHello random when message is HelloRetryRequest (RFC 8446 §4.1.3).
HRR_RANDOM: Final[bytes] = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)

#: Hard cap on a single TLS record body. RFC 8446 says ciphertext records
#: must be <= 2^14 + 256; we accept that.
MAX_RECORD_BODY: Final[int] = 16384 + 256


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TlsWireError(Exception):
    """Raised on malformed / unsupported TLS wire data.

    Carries a stable :attr:`status` string ("malformed", "refused",
    "tls_version_unsupported") so the caller can map the failure to a
    :class:`~qwashed.audit.schemas.ProbeStatus`.
    """

    def __init__(self, message: str, *, status: str = "malformed") -> None:
        super().__init__(message)
        self.status = status


# ---------------------------------------------------------------------------
# Wire encoding helpers
# ---------------------------------------------------------------------------


def _u8(x: int) -> bytes:
    return struct.pack(">B", x)


def _u16(x: int) -> bytes:
    return struct.pack(">H", x)


def _u24(x: int) -> bytes:
    return struct.pack(">I", x)[1:]


def _vec8(data: bytes) -> bytes:
    return _u8(len(data)) + data


def _vec16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _vec24(data: bytes) -> bytes:
    return _u24(len(data)) + data


# ---------------------------------------------------------------------------
# ClientHello assembly
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ClientHelloMaterial:
    """Materials retained after sending CH so we can finish the handshake.

    Attributes
    ----------
    record_bytes:
        Full TLS record (5-byte header + handshake message) ready to write
        to the socket.
    handshake_message:
        Just the handshake message (no record header) — used as the first
        chunk of the TLS 1.3 transcript hash.
    x25519_priv:
        Private key for the X25519 key_share offered in CH.
    """

    record_bytes: bytes
    handshake_message: bytes
    x25519_priv: X25519PrivateKey


def build_client_hello(server_name: str) -> ClientHelloMaterial:
    """Build a TLS 1.3 / 1.2 dual ClientHello with X25519 key_share.

    Offers TLS 1.3 (preferred) and TLS 1.2 (fallback); a small set of
    AEAD cipher suites for both versions; X25519 + secp256r1 +
    X25519MLKEM768 in supported_groups (X25519 is the actually-offered
    key_share); the standard signature_algorithms set; and the modern
    ``psk_dhe_ke`` exchange mode.

    Parameters
    ----------
    server_name:
        Hostname for SNI. Must be an ASCII label (RFC 6066). IP literals
        cause Qwashed to omit SNI rather than send a non-conforming label.
    """
    x25519_priv = X25519PrivateKey.generate()
    x25519_pub_bytes = x25519_priv.public_key().public_bytes_raw()

    random_bytes = secrets.token_bytes(32)
    # TLS 1.3 "compatibility mode": send a fresh 32-byte legacy_session_id
    # so middleboxes that remember TLS 1.2-shaped flows do not panic.
    session_id = secrets.token_bytes(32)

    cipher_suites = b"".join(
        _u16(c)
        for c in (
            CIPHER_TLS13_AES_128_GCM_SHA256,
            CIPHER_TLS13_AES_256_GCM_SHA384,
            CIPHER_TLS12_ECDHE_RSA_AES128_GCM_SHA256,
            CIPHER_TLS12_ECDHE_ECDSA_AES128_GCM_SHA256,
            CIPHER_TLS12_ECDHE_RSA_AES256_GCM_SHA384,
            CIPHER_TLS12_ECDHE_ECDSA_AES256_GCM_SHA384,
        )
    )
    extensions: list[bytes] = []

    # SNI — only if the hostname is a valid DNS label (not an IP literal).
    if _is_valid_sni(server_name):
        sni_entry = _u8(0) + _vec16(server_name.encode("ascii"))
        extensions.append(_u16(EXT_SERVER_NAME) + _vec16(_vec16(sni_entry)))

    # supported_versions: TLS 1.3, TLS 1.2
    sv = _vec8(_u16(TLS_1_3) + _u16(TLS_1_2))
    extensions.append(_u16(EXT_SUPPORTED_VERSIONS) + _vec16(sv))

    # supported_groups
    sg = _vec16(
        b"".join(
            _u16(g)
            for g in (
                GROUP_X25519,
                GROUP_X25519MLKEM768,
                GROUP_SECP256R1,
                GROUP_SECP384R1,
            )
        )
    )
    extensions.append(_u16(EXT_SUPPORTED_GROUPS) + _vec16(sg))

    # signature_algorithms
    sa = _vec16(b"".join(_u16(a) for a in SIG_ALGOS_OFFERED))
    extensions.append(_u16(EXT_SIGNATURE_ALGORITHMS) + _vec16(sa))

    # key_share: single X25519 entry
    ks_entry = _u16(GROUP_X25519) + _vec16(x25519_pub_bytes)
    ks = _vec16(ks_entry)
    extensions.append(_u16(EXT_KEY_SHARE) + _vec16(ks))

    # psk_key_exchange_modes: psk_dhe_ke (TLS 1.3 strongly recommends sending)
    pkm = _vec8(_u8(1))
    extensions.append(_u16(EXT_PSK_KEY_EXCHANGE_MODES) + _vec16(pkm))

    extensions_bytes = b"".join(extensions)

    # legacy_compression_methods<1..2^8-1>: send "null" (value 0) only.
    ch_body = (
        _u16(TLS_1_2)  # legacy_version
        + random_bytes
        + _vec8(session_id)
        + _vec16(cipher_suites)
        + _vec8(b"\x00")
        + _vec16(extensions_bytes)
    )

    hs_msg = _u8(HS_CLIENT_HELLO) + _vec24(ch_body)
    record = _u8(RECORD_HANDSHAKE) + _u16(TLS_1_2) + _vec16(hs_msg)

    return ClientHelloMaterial(
        record_bytes=record,
        handshake_message=hs_msg,
        x25519_priv=x25519_priv,
    )


def _is_valid_sni(hostname: str) -> bool:
    """True if ``hostname`` is suitable for the TLS SNI extension.

    Rejects IPv4 / IPv6 literals (RFC 6066 §3) and non-ASCII labels.
    """
    if not hostname:
        return False
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError:
        return False
    # IPv4 literal heuristic: all dot-separated parts numeric.
    parts = hostname.split(".")
    if all(p.isdigit() for p in parts) and 1 <= len(parts) <= 4:
        return False
    # IPv6 literal: contains colons.
    return ":" not in hostname


# ---------------------------------------------------------------------------
# Record / handshake reading
# ---------------------------------------------------------------------------


def _recv_exact(sock: socket.socket, n: int, budget: list[int]) -> bytes:
    """Read exactly ``n`` bytes from ``sock`` or raise.

    ``budget`` is a one-element list tracking the running total bytes read
    from the socket so the caller can enforce a global cap.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise TlsWireError("connection closed mid-record", status="malformed")
        buf.extend(chunk)
        budget[0] += len(chunk)
    return bytes(buf)


def read_record(
    sock: socket.socket, budget: list[int], *, max_total: int
) -> tuple[int, int, bytes]:
    """Read one TLS record from ``sock``.

    Returns ``(content_type, legacy_version, payload_bytes)``. Caller is
    responsible for translating an Alert record (content_type==21) into
    a :class:`TlsWireError` with ``status="refused"``.
    """
    header = _recv_exact(sock, 5, budget)
    content_type = header[0]
    version = struct.unpack(">H", header[1:3])[0]
    length = struct.unpack(">H", header[3:5])[0]
    if length > MAX_RECORD_BODY:
        raise TlsWireError(f"oversized record body {length}", status="malformed")
    if budget[0] + length > max_total:
        raise TlsWireError("server response exceeded byte budget", status="malformed")
    payload = _recv_exact(sock, length, budget)
    return content_type, version, payload


# ---------------------------------------------------------------------------
# ServerHello
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ServerHelloInfo:
    """Parsed ServerHello.

    ``selected_version`` is the genuine post-TLS-1.3 version (from the
    ``supported_versions`` extension); ``legacy_version`` is the on-wire
    ``ServerHello.legacy_version`` field, kept distinct for diagnostics.
    """

    legacy_version: int
    random_bytes: bytes
    cipher_suite: int
    selected_version: int
    selected_group: int | None
    server_pub_key: bytes | None
    is_hello_retry: bool


def parse_server_hello(body: bytes) -> ServerHelloInfo:
    """Parse a ServerHello handshake-message *body* (no record/HS header).

    Raises :class:`TlsWireError` on truncation or framing violation.
    """
    if len(body) < 38:
        raise TlsWireError("ServerHello too short", status="malformed")
    cur = 0
    legacy_version = struct.unpack(">H", body[cur : cur + 2])[0]
    cur += 2
    random_bytes = body[cur : cur + 32]
    cur += 32
    sid_len = body[cur]
    cur += 1
    if cur + sid_len + 3 > len(body):
        raise TlsWireError("ServerHello session_id overflow", status="malformed")
    cur += sid_len
    cipher_suite = struct.unpack(">H", body[cur : cur + 2])[0]
    cur += 2
    cur += 1  # legacy_compression_method

    selected_version = legacy_version
    selected_group: int | None = None
    server_pub_key: bytes | None = None
    is_hello_retry = random_bytes == HRR_RANDOM

    if cur >= len(body):
        # Pre-TLS-1.3 servers may omit the extensions field entirely.
        return ServerHelloInfo(
            legacy_version=legacy_version,
            random_bytes=random_bytes,
            cipher_suite=cipher_suite,
            selected_version=selected_version,
            selected_group=None,
            server_pub_key=None,
            is_hello_retry=is_hello_retry,
        )

    ext_total = struct.unpack(">H", body[cur : cur + 2])[0]
    cur += 2
    if cur + ext_total > len(body):
        raise TlsWireError("ServerHello extensions overflow", status="malformed")
    end = cur + ext_total

    while cur < end:
        if cur + 4 > end:
            raise TlsWireError("ServerHello ext header overflow", status="malformed")
        ext_type = struct.unpack(">H", body[cur : cur + 2])[0]
        cur += 2
        ext_len = struct.unpack(">H", body[cur : cur + 2])[0]
        cur += 2
        if cur + ext_len > end:
            raise TlsWireError("ServerHello ext body overflow", status="malformed")
        ext_data = body[cur : cur + ext_len]
        cur += ext_len

        if ext_type == EXT_SUPPORTED_VERSIONS:
            if len(ext_data) != 2:
                raise TlsWireError("supported_versions wrong length", status="malformed")
            selected_version = struct.unpack(">H", ext_data)[0]
        elif ext_type == EXT_KEY_SHARE:
            if len(ext_data) < 4:
                raise TlsWireError("key_share too short", status="malformed")
            selected_group = struct.unpack(">H", ext_data[:2])[0]
            kl = struct.unpack(">H", ext_data[2:4])[0]
            if 4 + kl > len(ext_data):
                raise TlsWireError("key_share entry overflow", status="malformed")
            server_pub_key = ext_data[4 : 4 + kl]

    return ServerHelloInfo(
        legacy_version=legacy_version,
        random_bytes=random_bytes,
        cipher_suite=cipher_suite,
        selected_version=selected_version,
        selected_group=selected_group,
        server_pub_key=server_pub_key,
        is_hello_retry=is_hello_retry,
    )


# ---------------------------------------------------------------------------
# Handshake message reassembly
# ---------------------------------------------------------------------------


class HandshakeReader:
    """Pulls handshake messages out of a stream of cleartext TLS records.

    A handshake message can be fragmented across records, and one record
    can carry multiple back-to-back handshake messages. This class hides
    both cases. Fed cleartext handshake-record payloads via :meth:`feed`,
    yields ``(msg_type, msg_body, raw_msg)`` tuples from :meth:`messages`
    where ``raw_msg`` is the full handshake message bytes including its
    1-byte type and 3-byte length prefix (useful for transcript hashing).
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> None:
        self._buf.extend(data)

    def messages(self) -> list[tuple[int, bytes, bytes]]:
        out: list[tuple[int, bytes, bytes]] = []
        while True:
            if len(self._buf) < 4:
                return out
            msg_type = self._buf[0]
            length = int.from_bytes(self._buf[1:4], "big")
            if len(self._buf) < 4 + length:
                return out
            raw = bytes(self._buf[: 4 + length])
            body = bytes(self._buf[4 : 4 + length])
            del self._buf[: 4 + length]
            out.append((msg_type, body, raw))


# ---------------------------------------------------------------------------
# TLS 1.3 key schedule
# ---------------------------------------------------------------------------


def _hkdf_extract(salt: bytes, ikm: bytes, hash_name: str) -> bytes:
    """RFC 5869 HKDF-Extract."""
    digest_size = hashlib.new(hash_name).digest_size
    if not salt:
        salt = b"\x00" * digest_size
    return hmac.new(salt, ikm, hash_name).digest()


def _hkdf_expand_label(
    secret: bytes,
    label: bytes,
    context: bytes,
    length: int,
    hash_algo: type[hashes.HashAlgorithm],
) -> bytes:
    """RFC 8446 §7.1 HKDF-Expand-Label."""
    full_label = b"tls13 " + label
    hkdf_label = (
        struct.pack(">H", length)
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    expander = HKDFExpand(algorithm=hash_algo(), length=length, info=hkdf_label)
    return expander.derive(secret)


def derive_tls13_server_handshake_keys(
    *,
    shared_secret: bytes,
    transcript_hash_after_sh: bytes,
    cipher_suite: int,
) -> tuple[bytes, bytes]:
    """Derive the TLS 1.3 server-handshake AEAD key + static IV.

    Implements the prefix of the RFC 8446 §7.1 key schedule needed to
    decrypt the server's encrypted handshake records (EncryptedExtensions,
    Certificate, CertificateVerify, Finished). Returns
    ``(server_handshake_key, server_handshake_iv)``.
    """
    if cipher_suite not in TLS13_CIPHER_PARAMS:
        raise TlsWireError(
            f"unsupported TLS 1.3 cipher 0x{cipher_suite:04x}",
            status="malformed",
        )
    hash_algo, hash_name, key_len = TLS13_CIPHER_PARAMS[cipher_suite]
    digest_size = hashlib.new(hash_name).digest_size

    # Empty PSK -> early_secret = HKDF-Extract(salt=0, IKM=0)
    early_secret = _hkdf_extract(b"\x00" * digest_size, b"\x00" * digest_size, hash_name)
    empty_hash = hashlib.new(hash_name, b"").digest()
    derived = _hkdf_expand_label(early_secret, b"derived", empty_hash, digest_size, hash_algo)
    handshake_secret = _hkdf_extract(derived, shared_secret, hash_name)
    server_hs_traffic = _hkdf_expand_label(
        handshake_secret,
        b"s hs traffic",
        transcript_hash_after_sh,
        digest_size,
        hash_algo,
    )
    server_key = _hkdf_expand_label(server_hs_traffic, b"key", b"", key_len, hash_algo)
    server_iv = _hkdf_expand_label(server_hs_traffic, b"iv", b"", 12, hash_algo)
    return server_key, server_iv


# ---------------------------------------------------------------------------
# AES-GCM record decrypt for TLS 1.3 server -> client
# ---------------------------------------------------------------------------


def decrypt_tls13_record(
    payload: bytes,
    *,
    key: bytes,
    static_iv: bytes,
    seq: int,
) -> tuple[int, bytes]:
    """Decrypt one TLS 1.3 application-data record.

    Returns ``(inner_content_type, inner_plaintext)``. Strips the
    record-padding zero bytes per RFC 8446 §5.4.
    """
    if len(payload) < 17:
        # 1 byte minimum inner record + 16-byte AEAD tag
        raise TlsWireError("encrypted record too short", status="malformed")
    seq_bytes = struct.pack(">Q", seq)
    nonce_iv_xor = b"\x00" * 4 + seq_bytes
    nonce = bytes(a ^ b for a, b in zip(static_iv, nonce_iv_xor, strict=True))
    aad = (
        bytes([RECORD_APPLICATION_DATA])
        + struct.pack(">H", TLS_1_2)
        + struct.pack(">H", len(payload))
    )
    aesgcm = AESGCM(key)
    plaintext_with_type = aesgcm.decrypt(nonce, payload, aad)
    end = len(plaintext_with_type) - 1
    while end >= 0 and plaintext_with_type[end] == 0:
        end -= 1
    if end < 0:
        raise TlsWireError("inner record had no content_type", status="malformed")
    inner_type = plaintext_with_type[end]
    return inner_type, plaintext_with_type[:end]


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class CertificateInfo:
    """First (leaf) certificate from a Certificate handshake message."""

    leaf_der: bytes
    leaf_signature_algorithm_oid: str  # dotted-decimal OID


def parse_certificate_message(hs_body: bytes, *, tls13: bool) -> CertificateInfo:
    """Parse a Certificate handshake-message body and return the leaf cert.

    For TLS 1.3 the body is prefixed with a 1-byte
    ``certificate_request_context`` (always empty when the server is
    presenting its cert). For TLS 1.2 there is no such prefix.
    """
    cur = 0
    if tls13:
        if cur >= len(hs_body):
            raise TlsWireError("Certificate truncated (request context)", status="malformed")
        ctx_len = hs_body[cur]
        cur += 1
        if cur + ctx_len > len(hs_body):
            raise TlsWireError("Certificate request_context overflow", status="malformed")
        cur += ctx_len
    if cur + 3 > len(hs_body):
        raise TlsWireError("Certificate truncated (list len)", status="malformed")
    cert_list_len = int.from_bytes(hs_body[cur : cur + 3], "big")
    cur += 3
    if cur + cert_list_len > len(hs_body):
        raise TlsWireError("Certificate list overflow", status="malformed")
    end = cur + cert_list_len
    if cur + 3 > end:
        raise TlsWireError("Certificate list empty", status="malformed")
    cert_len = int.from_bytes(hs_body[cur : cur + 3], "big")
    cur += 3
    if cur + cert_len > end:
        raise TlsWireError("Certificate first entry overflow", status="malformed")
    leaf_der = hs_body[cur : cur + cert_len]

    cert = x509.load_der_x509_certificate(leaf_der)
    oid_dotted = cert.signature_algorithm_oid.dotted_string
    return CertificateInfo(
        leaf_der=leaf_der,
        leaf_signature_algorithm_oid=oid_dotted,
    )


# Cert-signature OIDs we recognise (RFC 5758, RFC 8410, RFC 4055).
CERT_SIG_ALGO_NAMES: Final[dict[str, str]] = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassa-pss",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
    # ML-DSA OIDs (NIST FIPS 204; OIDs assigned in CSOR 2.16.840.1.101.3.4.3)
    "2.16.840.1.101.3.4.3.17": "id-ml-dsa-44",
    "2.16.840.1.101.3.4.3.18": "id-ml-dsa-65",
    "2.16.840.1.101.3.4.3.19": "id-ml-dsa-87",
}


def cert_sig_algo_friendly_name(oid_dotted: str) -> str:
    """Return a stable name for a certificate signature OID, or ``oid:<dotted>``."""
    return CERT_SIG_ALGO_NAMES.get(oid_dotted, f"oid:{oid_dotted}")


# ---------------------------------------------------------------------------
# TLS 1.2 ServerKeyExchange parsing (ECDHE only)
# ---------------------------------------------------------------------------


def parse_server_key_exchange_named_curve(ske_body: bytes) -> int | None:
    """For an ECDHE ServerKeyExchange, return the named-curve ID (or None).

    Non-ECDHE ServerKeyExchange (e.g. DHE) is ignored here — the audit
    pipeline classifies it via the cipher suite name. Caller treats
    ``None`` as "named curve unknown".
    """
    if len(ske_body) < 4:
        return None
    curve_type = ske_body[0]
    if curve_type != 3:  # 3 = named_curve (RFC 4492 §5.4)
        return None
    return int(struct.unpack(">H", ske_body[1:3])[0])
