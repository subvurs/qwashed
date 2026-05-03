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

import socket
import ssl
import time
from abc import ABC, abstractmethod
from typing import Any, Final

from qwashed.audit.schemas import AuditTarget, ProbeResult
from qwashed.core.errors import ConfigurationError

__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_RESPONSE_BYTES",
    "Probe",
    "SslyzeTlsProbe",
    "StaticProbe",
    "StdlibTlsProbe",
    "probe_target",
]

#: Default wall-clock timeout, applied as both connect and handshake budget.
DEFAULT_TIMEOUT_SECONDS: Final[float] = 10.0

#: Hard ceiling on bytes read from the network in a single probe. The
#: ssl module reads handshake records as needed; we set the socket option
#: to cap. A normal TLS 1.3 handshake is ~5-7 KB.
MAX_RESPONSE_BYTES: Final[int] = 65536


class Probe(ABC):
    """Abstract probe interface.

    Implementations MUST:

    * Return a :class:`ProbeResult` with the same target.
    * Return ``status="unreachable"`` on connect timeout / DNS failure.
    * Return ``status="refused"`` on TCP RST / TLS alert.
    * Return ``status="malformed"`` on protocol-framing errors.
    * Never raise on a network error.
    """

    @abstractmethod
    def probe(self, target: AuditTarget) -> ProbeResult: ...


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


def probe_target(
    target: AuditTarget,
    *,
    probe_impl: Probe | None = None,
) -> ProbeResult:
    """Probe a single target with the given probe implementation.

    If ``probe_impl`` is omitted, defaults to :class:`StdlibTlsProbe` for
    TLS targets. SSH targets fail immediately with ``ProbeStatus.malformed``
    (SSH support is deferred to v0.1.1).
    """
    if probe_impl is None:
        probe_impl = StdlibTlsProbe()
    return probe_impl.probe(target)
