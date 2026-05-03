# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""``qwashed vault`` -- Hybrid post-quantum vault.

Local-only file/message store using hybrid cryptography:

- Encryption: X25519 || ML-KEM-768 (NIST FIPS 203), AEAD via AES-256-GCM
  with key derived from the concatenated KEM secrets via HKDF-SHA256.
- Signing:    Ed25519 || ML-DSA-65 (NIST FIPS 204), AND-verify (both
  components must verify).
- Audit log:  append-only, hash-chained (SHA3-256 over canonical JSON
  lines), every line hybrid-signed.

The hybrid construction means an attacker has to break both the classical
and the post-quantum component to compromise vault contents.

Modules (arriving in Phase 3 of the build plan):

- :mod:`qwashed.vault.hybrid_kem` -- X25519 || ML-KEM-768.
- :mod:`qwashed.vault.hybrid_sig` -- Ed25519 || ML-DSA-65.
- :mod:`qwashed.vault.store`      -- encrypted file/message store.
- :mod:`qwashed.vault.audit_log`  -- append-only, hash-chained audit log.
- :mod:`qwashed.vault.schemas`    -- Pydantic schemas.
- :mod:`qwashed.vault.cli`        -- ``qwashed vault`` subcommand handlers.
"""

from __future__ import annotations

__all__: list[str] = []
