# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Abstract probe interface, shared by all concrete probes.

Split out into its own module so the file-only probes
(:mod:`qwashed.audit.probe_pgp`, :mod:`qwashed.audit.probe_smime`)
can import the ABC without dragging in the TLS handshake stack from
:mod:`qwashed.audit.probe`.

Implementations MUST:

* Return a :class:`~qwashed.audit.schemas.ProbeResult` with the same target.
* Return ``status="unreachable"`` on connect timeout / DNS failure / file
  read failure.
* Return ``status="refused"`` on TCP RST / TLS alert.
* Return ``status="malformed"`` on protocol-framing / file-format errors.
* Never raise on a network or file error.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from qwashed.audit.schemas import AuditTarget, ProbeResult

__all__ = ["Probe"]


class Probe(ABC):
    """Abstract probe interface.

    Subclasses are expected to implement :meth:`probe` as an
    exception-safe operation that always returns a
    :class:`~qwashed.audit.schemas.ProbeResult`.
    """

    @abstractmethod
    def probe(self, target: AuditTarget) -> ProbeResult: ...
