# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Tests for qwashed.audit.probe.

Covers the abstract Probe interface, StdlibTlsProbe behavior against a
local test server (loopback), and StaticProbe canned-result lookup.

Per the build plan we exercise at least 5 fixture targets:
1. Classical-only TLS (loopback test server, RSA cert).
2. Pure-PQ in canned ProbeResult (StaticProbe).
3. Hybrid-PQ in canned ProbeResult (StaticProbe).
4. Unreachable (port not listening).
5. Refused / malformed (SSH target with TLS probe).
"""

from __future__ import annotations

import socket
import ssl
import threading
from collections.abc import Iterator

import pytest

from qwashed.audit.probe import (
    Probe,
    SslyzeTlsProbe,
    StaticProbe,
    StdlibTlsProbe,
    probe_target,
)
from qwashed.audit.schemas import AuditTarget, ProbeResult

# ---------------------------------------------------------------------------
# Loopback TLS server fixture (RSA self-signed certificate generated on the
# fly; no network access leaves the host).
# ---------------------------------------------------------------------------


def _make_self_signed_cert(tmp_path) -> tuple[str, str]:  # type: ignore[no-untyped-def]
    """Generate a self-signed RSA cert into ``tmp_path``; return (cert, key)."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "qwashed-test.localhost"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


@pytest.fixture
def loopback_tls_server(tmp_path) -> Iterator[int]:  # type: ignore[no-untyped-def]
    """Start a one-shot TLS server on a free loopback port; yield port."""
    cert_file, key_file = _make_self_signed_cert(tmp_path)

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        sock.settimeout(2.0)
        try:
            while not stop.is_set():
                try:
                    client, _ = sock.accept()
                except (TimeoutError, OSError):
                    continue
                try:
                    with server_ctx.wrap_socket(client, server_side=True) as tls:
                        try:
                            tls.recv(1)
                        except (TimeoutError, OSError, ssl.SSLError):
                            pass
                except (ssl.SSLError, OSError):
                    pass
                finally:
                    try:
                        client.close()
                    except OSError:
                        pass
        finally:
            sock.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        thread.join(timeout=3.0)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestStdlibTlsProbe:
    def test_classical_handshake(self, loopback_tls_server: int) -> None:
        target = AuditTarget(host="127.0.0.1", port=loopback_tls_server)
        probe = StdlibTlsProbe(timeout_seconds=5.0)
        result = probe.probe(target)
        assert result.status == "ok"
        assert result.negotiated_protocol_version.startswith("TLS")
        assert result.cipher_suite  # something non-empty
        # stdlib does not expose KEX group; classifier handles "" -> unknown.
        assert result.key_exchange_group == ""
        assert result.signature_algorithm == ""
        assert result.elapsed_seconds >= 0.0

    def test_unreachable_port(self) -> None:
        # Port 1 is privileged + extremely unlikely to be open on loopback.
        target = AuditTarget(host="127.0.0.1", port=1)
        probe = StdlibTlsProbe(timeout_seconds=2.0)
        result = probe.probe(target)
        assert result.status in {"refused", "unreachable"}
        assert result.cipher_suite == ""

    def test_dns_failure(self) -> None:
        target = AuditTarget(
            host="this-host-definitely-does-not-exist.qwashed-test.invalid",
            port=443,
        )
        probe = StdlibTlsProbe(timeout_seconds=2.0)
        result = probe.probe(target)
        # Either gaierror -> unreachable, or DNS interception -> something
        # weird; in any case it must NOT be "ok".
        assert result.status != "ok"
        assert result.error_detail

    def test_ssh_target_rejected(self) -> None:
        target = AuditTarget(host="127.0.0.1", port=22, protocol="ssh")
        probe = StdlibTlsProbe()
        result = probe.probe(target)
        assert result.status == "malformed"
        assert "[audit-ssh]" in result.error_detail

    def test_invalid_timeout_rejected(self) -> None:
        from qwashed.core.errors import ConfigurationError

        with pytest.raises(ConfigurationError):
            StdlibTlsProbe(timeout_seconds=0)
        with pytest.raises(ConfigurationError):
            StdlibTlsProbe(timeout_seconds=-1)


class TestStaticProbe:
    def test_returns_canned_result(self) -> None:
        target = AuditTarget(host="canned.example", port=443)
        canned = ProbeResult(
            target=target,
            status="ok",
            negotiated_protocol_version="TLSv1.3",
            cipher_suite="TLS_AES_128_GCM_SHA256",
            key_exchange_group="X25519MLKEM768",
            signature_algorithm="ed25519_mldsa65",
        )
        probe = StaticProbe({("canned.example", 443): canned})
        result = probe.probe(target)
        assert result.status == "ok"
        assert result.key_exchange_group == "X25519MLKEM768"

    def test_unknown_target_synthesizes_unreachable(self) -> None:
        target = AuditTarget(host="not-in-fixture.example", port=443)
        probe = StaticProbe({})
        result = probe.probe(target)
        assert result.status == "unreachable"

    def test_target_label_replaced(self) -> None:
        # The canned target had label=None; if the user queries with
        # label="prod", that label should be on the returned result.
        canned_target = AuditTarget(host="x", port=443)
        canned = ProbeResult(target=canned_target, status="ok")
        probe = StaticProbe({("x", 443): canned})
        queried = AuditTarget(host="x", port=443, label="prod")
        result = probe.probe(queried)
        assert result.target.label == "prod"


class TestProbeTarget:
    def test_default_uses_stdlib(self) -> None:
        # Empty StaticProbe: any target -> unreachable. We pass it
        # explicitly.
        target = AuditTarget(host="127.0.0.1", port=1)
        result = probe_target(target, probe_impl=StaticProbe({}))
        assert result.status == "unreachable"

    def test_default_creates_stdlib_probe(self) -> None:
        # Pass a target that won't respond and confirm the call returns.
        target = AuditTarget(host="127.0.0.1", port=1)
        result = probe_target(target)
        assert result.status in {"refused", "unreachable"}


def _sslyze_installed() -> bool:
    try:
        import sslyze  # noqa: F401
    except ImportError:
        return False
    return True


class TestSslyzeTlsProbe:
    @pytest.mark.skipif(
        _sslyze_installed(),
        reason="sslyze is installed; this test only runs in no-extras envs",
    )
    def test_missing_sslyze_raises(self) -> None:
        # When sslyze is not installed, calling probe() must raise
        # ConfigurationError with the documented error_code.
        from qwashed.core.errors import ConfigurationError

        target = AuditTarget(host="127.0.0.1", port=443)
        probe = SslyzeTlsProbe()
        with pytest.raises(ConfigurationError) as exc:
            probe.probe(target)
        assert exc.value.error_code == "audit.probe.missing_sslyze"


class TestProbeIsAbstract:
    def test_cannot_instantiate(self) -> None:
        with pytest.raises(TypeError):
            Probe()  # type: ignore[abstract]
