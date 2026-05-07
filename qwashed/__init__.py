# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""Qwashed: free post-quantum hygiene for civil society.

Two tools:

- :mod:`qwashed.audit` -- HNDL (Harvest-Now-Decrypt-Later) auditor. Probes
  TLS / SSH endpoints, classifies their cryptographic posture, scores
  exposure under a civil-society threat profile, and produces a signed
  migration roadmap.

- :mod:`qwashed.vault` -- Hybrid post-quantum vault. Local-only,
  hybrid-encrypted (X25519 || ML-KEM-768) and hybrid-signed
  (Ed25519 || ML-DSA-65) file/message store with a tamper-evident,
  hash-chained audit log.

The two modules share a small set of generic primitives in
:mod:`qwashed.core` (canonical JSON, signing, schemas, KDFs, reporting).

Status: v0.1.0 (alpha). See ``CHANGELOG.md``, ``QWASHED_BUILD_PLAN.txt``,
and ``THREAT_MODEL.md`` at the repository root.
"""

from __future__ import annotations

__all__ = [
    "__author__",
    "__license__",
    "__version__",
]

__version__: str = "0.2.0a1"
__author__: str = "Mark Eatherly"
__license__: str = "Apache-2.0"
