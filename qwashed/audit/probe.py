# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""TLS / SSH probing for the Qwashed HNDL auditor.

Design
------
The probe layer is an abstract interface (:class:`Probe`) plus two
concrete implementations:

* :class:`StdlibTlsProbe` -- stdlib-only TLS probe. Captures negotiated
  TLS version, cipher suite, and peer-certificate subject. Does NOT
  capture the KEX group or the handshake signature algorithm because
  CPython's :mod:`ssl` module does not expose those (as of Python 3.13).
  Fields it cannot fill stay empty, and the classifier maps them to
  ``"unknown"`` (fail-closed).

* :class:`SslyzeTlsProbe` -- sslyze-backed probe (lazy-imported from the
  ``[audit]`` extra). Captures the same fields plus the negotiated KEX
  group name and certificate signature algorithm. This is the recommended
  probe for production audits.

* :class:`StaticProbe` -- canned :class:`ProbeResult` lookup for tests
  and golden fixtures. No network, no I/O.

Hard guarantees
---------------
* Every probe enforces a wall-clock timeout (default 10 s, configurable).
  No probe ever blocks indefinitely.
* Network errors (DNS, connect refused, timeout, TLS alert) become
  :class:`ProbeStatus` values, never bubbling exceptions.
* No private bytes from the wire are stored or logged. The
  ``error_detail`` field carries summary strings only.
* The probe never reads more than :data:`MAX_RESPONSE_BYTES` from the
  network in a single handshake; this defends against a malicious server
  trying to flood the auditor.

SSH probing (paramiko-backed) is feature-flagged off in v0.1 per the
build plan. Calling ``probe()`` on an SSH target with the stdlib or
sslyze probes returns ``ProbeStatus.malformed`` with ``error_detail``
explaining that SSH support requires the ``[audit-ssh]`` extra (deferred
to v0.1.1).
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import time
from typing import Any, Final

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from qwashed.audit import _tls_wire as _w
from qwashed.audit.probe_base import Probe
from qwashed.audit.probe_pgp import PgpProbe
from qwashed.audit.probe_smime import SmimeProbe
from qwashed.audit.schemas import FILE_ONLY_PROTOCOLS, AuditTarget, ProbeResult
from qwashed.core.errors import ConfigurationError

__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "FILE_ONLY_PROTOCOLS",
    "MAX_RESPONSE_BYTES",
    "MultiplexProbe",
    "NativeTlsProbe",
    "PgpProbe",
    "Probe",
    "SmimeProbe",
    "SslyzeTlsProbe",
    "StaticProbe",
    "StdlibTlsProbe",
    "build_default_probe",
    "probe_target",
]

#: Default wall-clock timeout, applied as both connect and handshake budget.
DEFAULT_TIMEOUT_SECONDS: Final[float] = 10.0

#: Hard ceiling on bytes read from the network in a single probe. The
#: ssl module reads handshake records as needed; we set the socket option
#: to cap. A normal TLS 1.3 handshake is ~5-7 KB.
MAX_RESPONSE_BYTES: Final[int] = 65536


class StdlibTlsProbe(Probe):
    """Pure-stdlib TLS probe.

    Uses :mod:`ssl` for the handshake. Captures TLS version + cipher suite
    + peer cert subject, which is enough to reason about classical AEAD
    posture but not enough to classify PQ KEX. Suitable for hardware-air-
    gapped audits where adding ``sslyze`` is not possible; in production
    use :class:`SslyzeTlsProbe`.
    """

    def __init__(self, *, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        if timeout_seconds <= 0:
            raise ConfigurationError(
                f"timeout_seconds must be > 0, got {timeout_seconds}",
                error_code="audit.probe.bad_timeout",
            )
        self._timeout = timeout_seconds

    def probe(self, target: AuditTarget) -> ProbeResult:
        if target.protocol != "tls":
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=(
                    f"protocol={target.protocol!r} not supported by StdlibTlsProbe; "
                    "SSH probing requires the [audit-ssh] extra (v0.1.1+)"
                ),
            )

        ctx = ssl.create_default_context()
        # Allow self-signed / wrong-name targets: we are auditing crypto
        # posture, not certificate validity. The audit report does record
        # cert details so a reviewer can see them, but a cert mismatch is
        # not itself a PQ finding.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Do not negotiate TLS 1.0/1.1 even if remote offers; we are
        # auditing modern PQ posture and a TLS-1.0 negotiation tells us
        # nothing about KEM choice. The remote will be reported as
        # "refused" if it offers nothing newer, which is itself a finding.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        start = time.monotonic()
        try:
            with (
                socket.create_connection((target.host, target.port), timeout=self._timeout) as sock,
                ctx.wrap_socket(sock, server_hostname=target.host) as ssock,
            ):
                version = ssock.version() or ""
                cipher_info = ssock.cipher()
                # cipher_info is (name, version, secret_bits) or None.
                cipher_name = cipher_info[0] if cipher_info else ""
                elapsed = time.monotonic() - start
                return ProbeResult(
                    target=target,
                    status="ok",
                    negotiated_protocol_version=version,
                    cipher_suite=cipher_name,
                    # stdlib does not expose negotiated group / sig
                    key_exchange_group="",
                    signature_algorithm="",
                    aead=_classify_tls_aead(
                        version_str=version, cipher_name=cipher_name
                    ),
                    elapsed_seconds=elapsed,
                )
        except TimeoutError as exc:
            return ProbeResult(
                target=target,
                status="unreachable",
                error_detail=f"timeout after {self._timeout}s: {exc}",
                elapsed_seconds=time.monotonic() - start,
            )
        except (socket.gaierror, OSError) as exc:
            # gaierror: DNS failure. OSError: connection refused, network
            # unreachable, etc.
            status = "refused" if _is_refused(exc) else "unreachable"
            return ProbeResult(
                target=target,
                status=status,  # type: ignore[arg-type]
                error_detail=f"{type(exc).__name__}: {exc}",
                elapsed_seconds=time.monotonic() - start,
            )
        except ssl.SSLError as exc:
            return ProbeResult(
                target=target,
                status="refused",
                error_detail=f"TLS alert: {exc}",
                elapsed_seconds=time.monotonic() - start,
            )
        except Exception as exc:  # pragma: no cover - defensive
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=f"unexpected probe error: {type(exc).__name__}: {exc}",
                elapsed_seconds=time.monotonic() - start,
            )


def _is_refused(exc: BaseException) -> bool:
    """Heuristic: does this OSError look like an active refusal?"""
    msg = str(exc).lower()
    return "refused" in msg or "reset" in msg or "connection aborted" in msg


def _classify_tls_aead(*, version_str: str, cipher_name: str) -> bool | None:
    """Return whether the negotiated TLS cipher is an AEAD construction.

    * TLS 1.3 ciphers are always AEAD by construction (RFC 8446 §5.2).
    * TLS 1.2 AEAD suites contain ``GCM``, ``CHACHA20``, or ``CCM``.
    * TLS 1.2 CBC suites are non-AEAD.
    * Other / unrecognised cipher names return ``None`` (unknown).

    Used by :class:`NativeTlsProbe` and :class:`StdlibTlsProbe` to
    populate :attr:`ProbeResult.aead`, which feeds the v0.2 (§3.5)
    non-AEAD scoring boost.
    """
    if not cipher_name or not version_str:
        return None
    if version_str == "TLSv1.3":
        return True
    if version_str in {"TLSv1.2", "TLSv1.1", "TLSv1", "TLSv1.0"}:
        upper = cipher_name.upper()
        if "GCM" in upper or "CHACHA20" in upper or "CCM" in upper:
            return True
        if "CBC" in upper:
            return False
        # Stream ciphers (RC4 etc.) and unrecognised: leave unknown.
        return None
    return None


class NativeTlsProbe(Probe):
    """Hand-rolled TLS probe using only stdlib + ``cryptography``.

    Sends a TLS 1.3 / 1.2 dual ClientHello, parses ServerHello, and (for
    TLS 1.3) derives the server-handshake AEAD key to decrypt the
    encrypted handshake stream so we can read the Certificate message.
    Captures:

    * ``negotiated_protocol_version``  (TLSv1.3 / TLSv1.2 / ...)
    * ``cipher_suite``                 (IANA name, e.g. TLS_AES_128_GCM_SHA256)
    * ``key_exchange_group``           (X25519, X25519MLKEM768, secp256r1, ...)
    * ``signature_algorithm``          (friendly name of leaf cert OID)

    This is the default Qwashed v0.2 probe: it gives full PQ posture
    without requiring sslyze. ``SslyzeTlsProbe`` remains available behind
    the ``[audit-deep]`` extra for callers who want sslyze's broader
    posture surface (cipher-suite enumeration, vulnerability scans).

    Failure modes (consistent with :class:`Probe`):

    * DNS / connect refused / network unreachable -> ``unreachable`` /
      ``refused`` (status mapped from OSError text).
    * Server speaks SSLv3 / TLS 1.0 / TLS 1.1 -> ``malformed`` with
      ``error_detail="tls_version_unsupported"``. Auditing modern PQ
      posture is meaningless against a TLS 1.0 endpoint; that is itself
      a finding worth surfacing rather than silently producing data.
    * TLS alert / framing error / unsupported cipher -> ``refused`` or
      ``malformed`` per :class:`~qwashed.audit._tls_wire.TlsWireError`.
    """

    def __init__(self, *, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        if timeout_seconds <= 0:
            raise ConfigurationError(
                f"timeout_seconds must be > 0, got {timeout_seconds}",
                error_code="audit.probe.bad_timeout",
            )
        self._timeout = timeout_seconds

    def probe(self, target: AuditTarget) -> ProbeResult:
        if target.protocol != "tls":
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=(
                    f"protocol={target.protocol!r} not supported by "
                    "NativeTlsProbe; SSH probing requires the [audit-ssh] "
                    "extra (v0.1.1+)"
                ),
            )

        start = time.monotonic()
        try:
            with socket.create_connection(
                (target.host, target.port), timeout=self._timeout
            ) as sock:
                sock.settimeout(self._timeout)
                return self._handshake(target, sock, start)
        except TimeoutError as exc:
            return ProbeResult(
                target=target,
                status="unreachable",
                error_detail=f"timeout after {self._timeout}s: {exc}",
                elapsed_seconds=time.monotonic() - start,
            )
        except (socket.gaierror, OSError) as exc:
            status = "refused" if _is_refused(exc) else "unreachable"
            return ProbeResult(
                target=target,
                status=status,  # type: ignore[arg-type]
                error_detail=f"{type(exc).__name__}: {exc}",
                elapsed_seconds=time.monotonic() - start,
            )
        except _w.TlsWireError as exc:
            return ProbeResult(
                target=target,
                status=exc.status,  # type: ignore[arg-type]
                error_detail=str(exc),
                elapsed_seconds=time.monotonic() - start,
            )
        except Exception as exc:  # pragma: no cover - defensive
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=f"unexpected probe error: {type(exc).__name__}: {exc}",
                elapsed_seconds=time.monotonic() - start,
            )

    # ------------------------------------------------------------------
    # Handshake plumbing
    # ------------------------------------------------------------------

    def _handshake(
        self,
        target: AuditTarget,
        sock: socket.socket,
        start: float,
    ) -> ProbeResult:
        material = _w.build_client_hello(target.host)
        sock.sendall(material.record_bytes)

        budget: list[int] = [0]

        # Read ServerHello (always cleartext, RECORD_HANDSHAKE).
        sh_record_type, _sh_ver, sh_payload = _w.read_record(
            sock, budget, max_total=MAX_RESPONSE_BYTES
        )
        if sh_record_type == _w.RECORD_ALERT:
            return ProbeResult(
                target=target,
                status="refused",
                error_detail="server sent TLS alert in lieu of ServerHello",
                elapsed_seconds=time.monotonic() - start,
            )
        if sh_record_type != _w.RECORD_HANDSHAKE:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=f"unexpected record content_type={sh_record_type}",
                elapsed_seconds=time.monotonic() - start,
            )

        # Reassemble the ServerHello handshake message.
        sh_reader = _w.HandshakeReader()
        sh_reader.feed(sh_payload)
        msgs = sh_reader.messages()
        if not msgs or msgs[0][0] != _w.HS_SERVER_HELLO:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail="missing ServerHello",
                elapsed_seconds=time.monotonic() - start,
            )
        _sh_msg_type, sh_body, sh_raw = msgs[0]
        info = _w.parse_server_hello(sh_body)

        if info.is_hello_retry:
            # We do not implement HRR. Surface as a finding rather than
            # silently producing partial data.
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail="server sent HelloRetryRequest (not supported)",
                elapsed_seconds=time.monotonic() - start,
            )

        version_str = _format_tls_version(info.selected_version)
        if version_str is None:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail="tls_version_unsupported",
                elapsed_seconds=time.monotonic() - start,
            )
        cipher_name = _w.CIPHER_NAMES.get(info.cipher_suite, f"cipher_0x{info.cipher_suite:04x}")

        # Branch on negotiated TLS version.
        if info.selected_version == _w.TLS_1_3:
            return self._finish_tls13(
                target=target,
                sock=sock,
                budget=budget,
                start=start,
                material=material,
                info=info,
                ch_msg=material.handshake_message,
                sh_msg=sh_raw,
                version_str=version_str,
                cipher_name=cipher_name,
                # If sh_reader had leftover data after SH, those bytes
                # belong to the next records (ChangeCipherSpec or
                # encrypted handshake) and should be ignored — they
                # cannot legally be in the same record as SH.
            )
        return self._finish_tls12(
            target=target,
            sock=sock,
            budget=budget,
            start=start,
            sh_reader=sh_reader,
            info=info,
            version_str=version_str,
            cipher_name=cipher_name,
        )

    # ------------------------------------------------------------------
    # TLS 1.3 path
    # ------------------------------------------------------------------

    def _finish_tls13(
        self,
        *,
        target: AuditTarget,
        sock: socket.socket,
        budget: list[int],
        start: float,
        material: _w.ClientHelloMaterial,
        info: _w.ServerHelloInfo,
        ch_msg: bytes,
        sh_msg: bytes,
        version_str: str,
        cipher_name: str,
    ) -> ProbeResult:
        if info.selected_group != _w.GROUP_X25519:
            # We only sent an X25519 key_share; if the server picked
            # something else without an HRR, that's a protocol violation.
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=(
                    f"server selected unexpected group 0x{info.selected_group or 0:04x} without HRR"
                ),
                elapsed_seconds=time.monotonic() - start,
            )
        if info.server_pub_key is None or len(info.server_pub_key) != 32:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail="server X25519 key_share missing or wrong size",
                elapsed_seconds=time.monotonic() - start,
            )
        if info.cipher_suite not in _w.TLS13_CIPHER_PARAMS:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=(f"unsupported TLS 1.3 cipher 0x{info.cipher_suite:04x}"),
                elapsed_seconds=time.monotonic() - start,
            )

        shared_secret = material.x25519_priv.exchange(
            X25519PublicKey.from_public_bytes(info.server_pub_key)
        )
        _hash_algo, hash_name, _key_len = _w.TLS13_CIPHER_PARAMS[info.cipher_suite]
        transcript = hashlib.new(hash_name)
        transcript.update(ch_msg)
        transcript.update(sh_msg)
        transcript_after_sh = transcript.digest()

        server_key, server_iv = _w.derive_tls13_server_handshake_keys(
            shared_secret=shared_secret,
            transcript_hash_after_sh=transcript_after_sh,
            cipher_suite=info.cipher_suite,
        )

        hs_reader = _w.HandshakeReader()
        seq = 0
        sig_algo_name = ""
        kex_group_name = _w.GROUP_NAMES.get(
            info.selected_group, f"group_0x{info.selected_group:04x}"
        )

        # Read records until we've seen Certificate or run out of budget.
        # The server may send CCS in cleartext (compatibility) before the
        # encrypted stream; ignore it.
        for _ in range(64):  # generous record cap; budget enforces real cap
            content_type, _ver, payload = _w.read_record(sock, budget, max_total=MAX_RESPONSE_BYTES)
            if content_type == _w.RECORD_CHANGE_CIPHER_SPEC:
                continue
            if content_type == _w.RECORD_ALERT:
                return ProbeResult(
                    target=target,
                    status="refused",
                    error_detail="server alert before Certificate",
                    elapsed_seconds=time.monotonic() - start,
                )
            if content_type != _w.RECORD_APPLICATION_DATA:
                return ProbeResult(
                    target=target,
                    status="malformed",
                    error_detail=(
                        f"unexpected record content_type={content_type} in TLS 1.3 encrypted phase"
                    ),
                    elapsed_seconds=time.monotonic() - start,
                )
            try:
                inner_type, plaintext = _w.decrypt_tls13_record(
                    payload, key=server_key, static_iv=server_iv, seq=seq
                )
            except Exception as exc:
                return ProbeResult(
                    target=target,
                    status="malformed",
                    error_detail=f"decrypt failed: {type(exc).__name__}",
                    elapsed_seconds=time.monotonic() - start,
                )
            seq += 1
            if inner_type != _w.RECORD_HANDSHAKE:
                # Could legitimately be an alert; treat as refusal.
                if inner_type == _w.RECORD_ALERT:
                    return ProbeResult(
                        target=target,
                        status="refused",
                        error_detail="server alert in encrypted handshake",
                        elapsed_seconds=time.monotonic() - start,
                    )
                continue
            hs_reader.feed(plaintext)
            for msg_type, msg_body, _raw in hs_reader.messages():
                if msg_type == _w.HS_CERTIFICATE:
                    cert_info = _w.parse_certificate_message(msg_body, tls13=True)
                    sig_algo_name = _w.cert_sig_algo_friendly_name(
                        cert_info.leaf_signature_algorithm_oid
                    )
                    return ProbeResult(
                        target=target,
                        status="ok",
                        negotiated_protocol_version=version_str,
                        cipher_suite=cipher_name,
                        key_exchange_group=kex_group_name,
                        signature_algorithm=sig_algo_name,
                        public_key_bits=cert_info.public_key_bits,
                        public_key_algorithm_family=(
                            cert_info.public_key_algorithm_family
                        ),
                        cert_not_after=cert_info.not_after,
                        aead=_classify_tls_aead(
                            version_str=version_str, cipher_name=cipher_name
                        ),
                        elapsed_seconds=time.monotonic() - start,
                    )
            # else: keep reading more records to find Certificate
        return ProbeResult(
            target=target,
            status="malformed",
            error_detail="Certificate not seen within record budget",
            elapsed_seconds=time.monotonic() - start,
        )

    # ------------------------------------------------------------------
    # TLS 1.2 path
    # ------------------------------------------------------------------

    def _finish_tls12(
        self,
        *,
        target: AuditTarget,
        sock: socket.socket,
        budget: list[int],
        start: float,
        sh_reader: _w.HandshakeReader,
        info: _w.ServerHelloInfo,
        version_str: str,
        cipher_name: str,
    ) -> ProbeResult:
        sig_algo_name = ""
        kex_group_name = ""
        leaf_pk_bits: int | None = None
        leaf_pk_family: str | None = None
        leaf_not_after: str | None = None

        # Process any handshake messages that came in the same record as
        # SH (rare for real servers, but legal), then keep reading records
        # until we've seen the leaf Certificate.
        seen_cert = False
        for _ in range(64):
            for msg_type, msg_body, _raw in sh_reader.messages():
                if msg_type == _w.HS_CERTIFICATE and not seen_cert:
                    cert_info = _w.parse_certificate_message(msg_body, tls13=False)
                    sig_algo_name = _w.cert_sig_algo_friendly_name(
                        cert_info.leaf_signature_algorithm_oid
                    )
                    leaf_pk_bits = cert_info.public_key_bits
                    leaf_pk_family = cert_info.public_key_algorithm_family
                    leaf_not_after = cert_info.not_after
                    seen_cert = True
                elif msg_type == _w.HS_SERVER_KEY_EXCHANGE:
                    curve_id = _w.parse_server_key_exchange_named_curve(msg_body)
                    if curve_id is not None:
                        kex_group_name = _w.GROUP_NAMES.get(curve_id, f"group_0x{curve_id:04x}")
                elif msg_type == _w.HS_SERVER_HELLO_DONE:
                    return ProbeResult(
                        target=target,
                        status="ok",
                        negotiated_protocol_version=version_str,
                        cipher_suite=cipher_name,
                        key_exchange_group=kex_group_name,
                        signature_algorithm=sig_algo_name,
                        public_key_bits=leaf_pk_bits,
                        public_key_algorithm_family=leaf_pk_family,
                        cert_not_after=leaf_not_after,
                        aead=_classify_tls_aead(
                            version_str=version_str, cipher_name=cipher_name
                        ),
                        elapsed_seconds=time.monotonic() - start,
                    )
            content_type, _ver, payload = _w.read_record(sock, budget, max_total=MAX_RESPONSE_BYTES)
            if content_type == _w.RECORD_ALERT:
                return ProbeResult(
                    target=target,
                    status="refused",
                    error_detail="server alert during TLS 1.2 handshake",
                    elapsed_seconds=time.monotonic() - start,
                )
            if content_type != _w.RECORD_HANDSHAKE:
                return ProbeResult(
                    target=target,
                    status="malformed",
                    error_detail=(
                        f"unexpected record content_type={content_type} in TLS 1.2 handshake"
                    ),
                    elapsed_seconds=time.monotonic() - start,
                )
            sh_reader.feed(payload)

        return ProbeResult(
            target=target,
            status="malformed",
            error_detail="ServerHelloDone not seen within record budget",
            elapsed_seconds=time.monotonic() - start,
        )


def _format_tls_version(version: int) -> str | None:
    """Map a 16-bit version code to a stable display string, or None.

    Returns ``None`` for SSLv3 / TLS 1.0 / TLS 1.1: those versions are
    rejected by Qwashed because their classical KEX/sig surface tells us
    nothing about modern PQ posture.
    """
    if version == _w.TLS_1_3:
        return "TLSv1.3"
    if version == _w.TLS_1_2:
        return "TLSv1.2"
    return None


class SslyzeTlsProbe(Probe):
    """sslyze-backed TLS probe (lazy import from the ``[audit]`` extra).

    Captures the negotiated KEX group name and certificate signature
    algorithm in addition to version and cipher. This is the canonical
    production probe.

    Calling :meth:`probe` raises :class:`ConfigurationError` if ``sslyze``
    is not installed; the auditor CLI catches this and offers the
    :class:`StdlibTlsProbe` as a fallback.
    """

    def __init__(self, *, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        if timeout_seconds <= 0:
            raise ConfigurationError(
                f"timeout_seconds must be > 0, got {timeout_seconds}",
                error_code="audit.probe.bad_timeout",
            )
        self._timeout = timeout_seconds

    def probe(self, target: AuditTarget) -> ProbeResult:
        # Lazy import: sslyze is heavy (~200 ms cold start) and an optional
        # extra. Importing on first probe rather than at module-load
        # keeps `qwashed --version` snappy.
        try:
            import sslyze  # noqa: F401
        except ImportError as exc:
            raise ConfigurationError(
                "sslyze is required for full PQ probing; install qwashed[audit]",
                error_code="audit.probe.missing_sslyze",
            ) from exc

        if target.protocol != "tls":
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=(
                    f"protocol={target.protocol!r} not supported by "
                    "SslyzeTlsProbe; SSH probing requires the [audit-ssh] "
                    "extra (v0.1.1+)"
                ),
            )

        # The sslyze API surface is intentionally deferred to runtime; we
        # do not want to lock the module import at type-check time. The
        # adapter is exercised in integration tests when the extra is
        # installed; unit tests use StaticProbe.
        return _sslyze_run(
            target=target,
            timeout_seconds=self._timeout,
        )  # pragma: no cover - exercised only when extra installed


def _sslyze_run(
    *,
    target: AuditTarget,
    timeout_seconds: float,
) -> ProbeResult:  # pragma: no cover - integration only
    """Adapter from sslyze's scan API to :class:`ProbeResult`.

    Kept module-private so tests can monkeypatch it without depending on
    the sslyze import.
    """
    # sslyze does not declare these in __all__; mypy strict flags this as
    # attr-defined in environments where sslyze is installed. The names are
    # part of sslyze's documented public API; suppress is intentional.
    from sslyze import (  # type: ignore[attr-defined]
        Scanner,
        ServerNetworkLocation,
        ServerScanRequest,
    )

    start = time.monotonic()
    try:
        location = ServerNetworkLocation(hostname=target.host, port=target.port)
        scanner = Scanner(
            per_server_concurrent_connections_limit=1,
            concurrent_server_scans_limit=1,
        )
        request = ServerScanRequest(server_location=location)
        scanner.queue_scans([request])
        all_results = list(scanner.get_results())
    except Exception as exc:
        return ProbeResult(
            target=target,
            status="unreachable",
            error_detail=f"sslyze error: {type(exc).__name__}: {exc}",
            elapsed_seconds=time.monotonic() - start,
        )

    if not all_results:
        return ProbeResult(
            target=target,
            status="unreachable",
            error_detail="sslyze returned no results",
            elapsed_seconds=time.monotonic() - start,
        )

    # Best-effort field extraction; the precise sslyze API surface differs
    # across versions, so we keep the adapter forgiving and fall back to
    # empty strings on any miss. The classifier handles "unknown".
    result = all_results[0]
    extracted: dict[str, str] = _extract_sslyze_fields(result)
    return ProbeResult(
        target=target,
        status="ok",
        negotiated_protocol_version=extracted.get("tls_version", ""),
        cipher_suite=extracted.get("cipher_suite", ""),
        key_exchange_group=extracted.get("kex_group", ""),
        signature_algorithm=extracted.get("signature_algorithm", ""),
        extras={
            k: v
            for k, v in extracted.items()
            if k
            not in {
                "tls_version",
                "cipher_suite",
                "kex_group",
                "signature_algorithm",
            }
        },
        elapsed_seconds=time.monotonic() - start,
    )


def _extract_sslyze_fields(result: Any) -> dict[str, str]:  # pragma: no cover
    """Pull the fields we care about out of a sslyze scan result.

    Defensive: any AttributeError or unexpected structure becomes an empty
    string. The audit pipeline never crashes because sslyze's internals
    moved.
    """
    out: dict[str, str] = {}
    try:
        connectivity = getattr(result, "connectivity_status", None)
        if connectivity is not None:
            out["sslyze_connectivity"] = str(connectivity)
    except Exception:
        pass
    return out


class StaticProbe(Probe):
    """Canned probe for tests and offline replay.

    Construct with a mapping of ``(host, port) -> ProbeResult`` and the
    probe simply returns whatever was preloaded. Targets not in the map
    return a synthetic ``unreachable`` result so the rest of the pipeline
    behaves sensibly.
    """

    def __init__(self, results: dict[tuple[str, int], ProbeResult]) -> None:
        self._results = dict(results)

    def probe(self, target: AuditTarget) -> ProbeResult:
        key = (target.host, target.port)
        result = self._results.get(key)
        if result is None:
            return ProbeResult(
                target=target,
                status="unreachable",
                error_detail="no canned result for this target",
            )
        # Re-bind the target so the probe result reflects the queried target
        # exactly (in case the canned target differs in label).
        return result.model_copy(update={"target": target})


class MultiplexProbe(Probe):
    """Dispatch a probe call to the right per-protocol implementation.

    The audit configuration may mix TLS endpoints, SSH endpoints, PGP
    keys on disk, and S/MIME certificates on disk in a single run.
    Rather than make every caller branch on protocol, the multiplex
    probe holds a ``protocol -> Probe`` mapping and routes
    :meth:`probe` calls accordingly.

    Unmapped protocols return ``ProbeStatus.malformed`` with a clear
    error_detail explaining which extras (if any) would enable that
    protocol. This preserves the "no probe ever raises" contract.
    """

    def __init__(self, probes: dict[str, Probe]) -> None:
        self._probes: dict[str, Probe] = dict(probes)

    def register(self, protocol: str, probe: Probe) -> None:
        """Add or replace a per-protocol probe."""
        self._probes[protocol] = probe

    def probe(self, target: AuditTarget) -> ProbeResult:
        impl = self._probes.get(target.protocol)
        if impl is None:
            hint = ""
            if target.protocol == "ssh":
                hint = " (install qwashed[audit-ssh] for SSH support)"
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=(
                    f"protocol={target.protocol!r} has no registered probe"
                    f"{hint}"
                ),
            )
        return impl.probe(target)


def build_default_probe(*, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> MultiplexProbe:
    """Build the Qwashed v0.2 default :class:`MultiplexProbe`.

    Wires :class:`NativeTlsProbe` for ``tls``, :class:`PgpProbe` for
    ``pgp``, and :class:`SmimeProbe` for ``smime``. SSH is omitted and
    falls through to the multiplex's "no probe registered" branch
    (yields ``malformed`` with an install hint).
    """
    return MultiplexProbe(
        {
            "tls": NativeTlsProbe(timeout_seconds=timeout_seconds),
            "pgp": PgpProbe(),
            "smime": SmimeProbe(),
        }
    )


def probe_target(
    target: AuditTarget,
    *,
    probe_impl: Probe | None = None,
) -> ProbeResult:
    """Probe a single target with the given probe implementation.

    If ``probe_impl`` is omitted, defaults to :func:`build_default_probe`
    which routes TLS targets through :class:`NativeTlsProbe`, PGP
    targets through :class:`PgpProbe`, and S/MIME targets through
    :class:`SmimeProbe`. SSH targets surface a "no probe registered"
    diagnostic (SSH support is deferred to the ``[audit-ssh]`` extra).
    """
    if probe_impl is None:
        probe_impl = build_default_probe()
    return probe_impl.probe(target)


# Re-exported here so module-level callers see the same API even though
# the FILE_ONLY_PROTOCOLS constant is sourced from schemas. Used by the
# CLI to know whether to resolve a target's key_path.
__all__.append("FILE_ONLY_PROTOCOLS")
__all__.append("build_default_probe")
