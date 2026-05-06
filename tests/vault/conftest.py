# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
#
# Vault tests require the optional `qwashed[vault]` extra (specifically
# `liboqs-python`, which provides the `oqs` module used by hybrid_kem
# and hybrid_sig for ML-KEM-768 / ML-DSA-65 NIST PQC primitives).
#
# When pytest is invoked in environments that intentionally install only
# the core `[dev]` extras — e.g. the `test-no-net` CI job that enforces
# the no-telemetry policy without pulling in network-capable audit/vault
# dependencies — `oqs` will be unavailable. Skip the entire vault test
# package in that case rather than failing collection.
#
# This conftest.py runs before any test modules under tests/vault/ are
# imported, so pytest.importorskip prevents ImportError at collection
# time on hybrid_kem / hybrid_sig modules that do `import oqs`.

import pytest

pytest.importorskip(
    "oqs",
    reason="vault tests require liboqs-python (install qwashed[vault] extra)",
)
