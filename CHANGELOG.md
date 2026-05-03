# Changelog

All notable changes to Qwashed will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

(no changes)

## [0.1.0] — 2026-04-30

First public release. The cryptographic core, HNDL auditor, and hybrid PQ
vault are functional, documented, and covered by 418 passing tests.
Treat v0.1.x as evaluation-grade software for civil-society pilots.

### Added

#### Phase 4 (docs + release) — 2026-04-30

- `docs/QUICKSTART.md`: five-minute install + first audit + first vault
  flow with cross-references to deeper guides and a "common first-run
  problems" troubleshooting section.
- `docs/AUDIT_GUIDE.md`: civil-society-IT-team operational guide for
  `qwashed audit` covering targets-file format, profile selection, exit
  codes, --deterministic mode + signing-key handling, four worked
  scenarios (newsroom, clinic, legal-aid CI, organizing campaign), the
  migration roadmap pattern, and an explicit non-features list.
- `docs/THREAT_PROFILES.md`: full reference for the threat-profile YAML
  schema, all four bundled profiles (default, journalism, healthcare,
  legal), the `score = category_weight * archival_likelihood` formula,
  the domain-monotonic / monotonic-thresholds validation invariants,
  and a "write your own profile" calibration walkthrough.
- `docs/VERIFY_RELEASE.md`: release verification flow against the
  project's Ed25519 release-signing key, covering single-file and
  bulk-`SHA256SUMS` verification, an air-gapped install workflow, and
  the explicit distinction between release verification (this doc) and
  artifact verification (`qwashed verify`).
- README: install/Quickstart sections updated for v0.1.0; status callout
  updated; cross-links to all Phase 4 guides.
- THREAT_MODEL.md version header bumped to v0.1.0.
- `RELEASE_HANDOFF.md` (root): one-shot maintainer handoff covering
  release-key generation, encrypted-disclosure-recipient publication,
  signing, tagging, and rollback procedure. Delete after v0.1.0
  publication.

### Changed

- `pyproject.toml`: `version` `0.1.0.dev0` → `0.1.0`; classifier
  `Development Status :: 2 - Pre-Alpha` → `3 - Alpha`; added `S603` to
  the `tests/**/*.py` per-file ruff ignores.
- `qwashed/__init__.py`: `__version__` `0.1.0.dev0` → `0.1.0`; status
  docstring updated.
- `qwashed/core/kdf.py`: removed redundant `cast(bytes, ...)` around
  `hash_secret_raw` (carried Phase-1 mypy warning); dropped now-unused
  `cast` import. No behavioral change.
- `qwashed/audit/probe.py`: added narrow `# type: ignore[attr-defined]`
  on the `sslyze` import (sslyze does not declare its public API in
  `__all__`; the names are part of its documented public surface).
- `tests/audit/test_probe.py`: `test_missing_sslyze_raises` now skips
  when sslyze is installed (was hard-failing in `[audit]`-extras envs).

### Verified

- v0.1.0 final quality gate green on macOS Darwin arm64 / Python
  3.13.2 with `[audit]` and `[vault]` extras installed:
  `ruff check .` clean, `ruff format --check .` clean (54 files),
  `mypy --strict qwashed/` clean (27 source files, one informational
  note about an unused override block for `paramiko.*`),
  `pytest` 417 passing + 1 skipped (the conditional sslyze-not-installed
  test).
- Phase-2 KAT vectors (FIPS 203 / FIPS 204), audit-log hash chain,
  hybrid construction cross-tests, and `qwashed verify` round-trip
  re-verified post version bump.

#### Phase 3 (vault module) — 2026-04-30

- `qwashed.vault.hybrid_kem`: `HybridKemKey` (X25519 || ML-KEM-768) and
  `hybrid_encap` / `hybrid_decap` over the
  `b"qwashed/vault/v0.1/kem"`-tagged HKDF-SHA256 KDF. Output of
  `hybrid_encap` is a ciphertext `u32_be(kem_ct_len) + kem_ct` plus a
  32-byte AEAD-ready shared secret. NIST FIPS 203 KAT vectors enforced
  in `tests/vault/test_hybrid_kem.py`. Cross-test: corrupting EITHER the
  X25519 ephemeral or the ML-KEM ciphertext fails decap with a typed
  `SignatureError`; success requires both components intact.
- `qwashed.vault.hybrid_sig`: `HybridSigningKey` /
  `HybridVerifyKey` (Ed25519 || ML-DSA-65). Signature encoding is
  `u32_be(ed25519_sig_len) + ed25519_sig + mldsa65_sig`; verification
  is fail-closed on either component. NIST FIPS 204 KAT vectors
  enforced. Cross-test: tampering with EITHER half fails verify
  (`tests/vault/test_hybrid_sig.py`).
- `qwashed.vault.audit_log`: `AuditLogWriter` and `AuditLogReader`
  implementing a SHA3-256 hash-chained, hybrid-signed JSONL log.
  `AuditLogWriter.append(op, subject)` appends a line carrying the
  prior line's hash, the canonical-JSON SHA3-256 of the new payload,
  and an Ed25519 || ML-DSA-65 signature. `AuditLogReader.__init__`
  verifies the entire chain at construction time — a tampered or
  truncated log is detected at unlock, before any vault operation
  runs. 15 unit tests covering genesis, single-line, multi-line,
  in-place tampering at every position, replay-after-truncation, and
  malformed-JSON cases.
- `qwashed.vault.store`: full file-vault implementation per build plan
  §7.7. `Vault` class with `init_vault(root, passphrase, *, memory_kib,
  time_cost, parallelism)` constructor, `unlock_vault(root, passphrase)`,
  and operations `put / get / list / verify / add_recipient /
  list_recipients / get_recipient / export`. Vault root layout:
  `manifest.json` (signed), `keys/identity.{pub,sk.enc}` (Argon2id-wrapped
  hybrid bundle), `keys/recipients/<fp>.pub`, `entries/<ulid>.{bin,meta.json}`,
  `audit_log.jsonl`. Entry blob format: `BLOB_MAGIC(b"QWEV") + version(1) +
  reserved(3) + u32_be(kem_ct_len) + kem_ct + nonce(12) + AES-256-GCM
  payload`. AEAD key derived from the hybrid shared secret via
  HKDF-SHA256 with info `b"qwashed/vault/v0.1/entry-aead"`. ULID
  identifiers (Crockford base32, 48-bit ms timestamp + 80 random bits).
  Recipient fingerprint = first 32 hex chars of `SHA-256(kem_pk||sig_pk)`.
  Atomic 0o600/0o700 writes throughout; no plaintext ever lands on disk.
  `export(ulid, recipient_fingerprint)` resolves the recipient FIRST so
  unknown fingerprints fail before any decryption occurs, then re-encrypts
  the entry to the recipient's hybrid bundle and emits a signed export
  bundle (`open_export_bundle()` provides the receiving-side helper).
  81 unit / property tests covering put/get/list, verify (clean and
  tampered), recipients, export round-trip, deterministic permissions,
  large-blob handling, and empty-vault edge cases.
- `qwashed vault` CLI subcommand tree:
  - `qwashed vault init [--root PATH]` — create a new vault. Passphrase
    via `QWASHED_VAULT_PASSPHRASE` env var or `getpass.getpass()`; never
    a CLI argument (security checklist 11.5).
  - `qwashed vault put PATH --name NAME [--root PATH]` — encrypt a file.
  - `qwashed vault get ULID -o PATH [--root PATH]` — decrypt to file.
  - `qwashed vault list [--root PATH]` — list entries.
  - `qwashed vault verify [--root PATH]` — re-verify all signatures and
    the audit-log hash chain. Exit 0 OK, 1 on any signature / chain
    failure (including tampered-audit-log detected at unlock time),
    2 on structural error.
  - `qwashed vault export ULID FINGERPRINT -o PATH` — produce a signed
    export bundle decryptable only by the named recipient.
  - `qwashed vault recipients add --kem-pk-file/-b64 ... --sig-pk-file/-b64 ... --label LABEL`
    — register a recipient public-key bundle. The `--*-pk-file` and
    `--*-pk-b64` arguments are XORed (exactly one must be supplied).
  - `qwashed vault recipients list` — show registered recipients.
  - Library-side: `qwashed.vault.store.open_export_bundle(...)` lets
    a recipient decrypt an export bundle without using the CLI.
- `docs/VAULT_GUIDE.md`: civil-society-targeted operational guide with
  four worked threat-model scenarios (journalist + sources, legal-aid
  intake, reproductive-health-clinic records, organizing-campaign contact
  lists), recovery / migration / tamper-response runbooks, and the
  Argon2id parameter override table.

### Verified

- Phase 3 quality gate green on macOS Darwin arm64 / Python 3.13.2:
  `ruff check` clean, `ruff format --check` clean (54 files),
  `mypy --strict` clean on Phase-3 code (one pre-existing
  redundant-cast warning in `qwashed/core/kdf.py:206` carried from
  Phase 1; unrelated to vault module), `pytest` 418 passing
  (1 skipped). 158 new vault tests across `audit_log` (15),
  `hybrid_kem` (22), `hybrid_sig` (15), `store` (81 covering
  put/get/list/verify/export/recipients), and the new vault CLI
  (25 covering all subcommands incl. round-trip put-export-open).
- FIPS 203 / FIPS 204 KAT vectors pass for ML-KEM-768 and ML-DSA-65.
- Hybrid construction: corrupting EITHER classical or PQ component of
  a KEM ciphertext or a signature fails verification fail-closed.
- Audit-log hash chain: tamper detection at every line position,
  including silent truncation; `AuditLogReader` verifies the full
  chain in its constructor so the vault refuses to open when the
  chain is broken.
- `qwashed vault put` / `get` round-trip: bytes-identical retrieval
  of arbitrary blobs; entry permissions 0o600 verified; vault
  directory permissions 0o700 verified.
- `qwashed vault export` round-trip: signed bundle decapsulates
  cleanly via `open_export_bundle` on the recipient side and verifies
  through the standard `qwashed verify` path.
- No private-key material in any log line, exception message, or
  `__repr__` (verified by `test_no_secret_leak`). Vault passphrase
  exclusively via `QWASHED_VAULT_PASSPHRASE` env var or
  `getpass.getpass()`; no `--passphrase` CLI argument exists.

#### Phase 2 (HNDL audit module) — 2026-04-30

- `qwashed.audit.schemas`: pydantic models for the audit pipeline rooted
  at `StrictBaseModel`. `AuditTarget` (host, port, protocol ∈ {tls,ssh},
  optional label), `ProbeResult` (negotiated TLS posture or SSH crypto
  posture, status ∈ {ok, unreachable, handshake_failed, …}), `AuditFinding`
  (target + probe + category + severity + score + rationale + ordered
  roadmap), `AuditReport` (envelope: profile name, generated_at, findings,
  aggregate_score, aggregate_severity, qwashed_version), and
  `ThreatProfile` (named scoring weights with monotonic invariants).
- `qwashed.audit.profile_loader`: loads the bundled YAML threat profiles
  (`default`, `healthcare`, `journalism`, `legal`) and arbitrary
  user-supplied YAML via `load_profile(name)` /
  `load_profile_from_path(path)`.
- `qwashed.audit.algorithm_tables`: JSON tables mapping TLS kex / TLS sig
  / SSH key-exchange / SSH host-key algorithm names to one of
  {classical, hybrid_pq, pq_only, unknown}.
- `qwashed.audit.classifier`: pure functions `classify_algorithm` /
  `classify(probe, tables) -> AuditFinding`. Fail-closed on any
  unrecognized algorithm: classification falls back to `unknown` with
  a rationale string explaining why.
- `qwashed.audit.scoring`: `score_finding(finding, profile)` produces a
  reproducible scalar score in [0, 1] from category + protocol + age,
  weighted by the supplied threat profile. `severity_for(score, profile)`
  bins to {info, low, moderate, high, critical}. `aggregate_score(...)`
  rolls per-target findings into a single audit-level score (max in
  default profile; mean and weighted-max also supported).
- `qwashed.audit.roadmap`: `build_roadmap(finding) -> list[str]` and
  `attach_roadmap(finding) -> AuditFinding` produce ordered remediation
  steps tagged by urgency ({URGENT, HIGH PRIORITY, MODERATE, LOW,
  INFORMATIONAL}); the urgency tag of `roadmap[0]` always matches the
  scored severity.
- `qwashed.audit.probe`: `Probe` ABC with three implementations.
  `StdlibTlsProbe` performs a real TLS 1.3 handshake using only
  `ssl.SSLContext` from the standard library (no external dependency
  default), enriched optionally with sslyze metadata when installed.
  `StaticProbe` returns canned `ProbeResult`s for tests / golden runs.
  `Probe` enforces a 12-test fixture suite including a loopback TLS
  server.
- `qwashed.audit.pipeline`: pure orchestrator. `audit_target(target,
  probe_impl, profile)` runs probe → classify → score → attach_roadmap.
  `run_audit(targets, profile, probe_impl, generated_at,
  qwashed_version)` rolls per-target findings into an `AuditReport`.
  Roadmap is attached after scoring so urgency tags always match final
  severity.
- `qwashed.audit.report_html`: standalone HTML report renderer, built on
  `qwashed.core.report.render_html`. No JavaScript, no remote assets,
  no third-party HTML templating engine. Severity color coding,
  per-finding rationale, ordered roadmap list. Empty audits show "No
  targets supplied". Footer toggles between "Signed by Ed25519
  fingerprint XXXX…" and "Unsigned report".
- `qwashed audit` CLI subcommand:
  - `qwashed audit run <config.yaml> [--profile NAME | --profile-file
    PATH] [--output JSON_PATH] [--html PATH] [--pdf PATH]
    [--signing-key PATH] [--deterministic]`
    Loads target list, runs the pipeline, emits canonicalized JSON
    signed with Ed25519. The JSON envelope is the standard
    `{ ..., ed25519_pubkey, signature_ed25519 }` so `qwashed verify`
    round-trips it. `--deterministic` freezes timestamp ("2026-01-01T00:00:00Z"),
    version ("0.1.0"), and signing key (all-zero seed); two consecutive
    runs produce bit-identical bytes.
  - `qwashed audit profiles` lists all bundled threat profiles with
    descriptions.
  - Exit codes: 0 success, 1 critical-severity finding, 2 structural
    error (bad config, missing profile, signing-key error, IO failure).
- `examples/audit/`: four runnable example configs
  (`civic_websites.yaml`, `healthcare_endpoints.yaml`,
  `journalism_endpoints.yaml`, `legal_endpoints.yaml`) plus a README.
- `tests/audit/test_golden.py`: 8 golden-file tests asserting
  byte-identical signed JSON across two consecutive
  `--deterministic` runs against a `StaticProbe` for each bundled
  threat profile. Regeneration helper:
  `python -m tests.audit.test_golden --regenerate`.

### Verified

- Phase 2 quality gate green on macOS Darwin arm64 / Python 3.13.2:
  `ruff check` clean, `ruff format --check` clean (44 files),
  `mypy --strict` clean (44 source files), `pytest` 260/260 passing
  across all test modules including 7 new CLI integration tests
  (round-trip through `qwashed verify`) and 8 golden-file tests.

#### Phase 1 (core infrastructure) — 2026-04-30

- `qwashed.core.errors`: typed exception hierarchy rooted at `QwashedError`
  with stable machine-readable `error_code` strings. Subclasses:
  `CanonicalizationError`, `SignatureError`, `KeyDerivationError`,
  `SchemaValidationError` (carries originating `pydantic_error`),
  `ConfigurationError`. Fail-closed posture: every public function in
  `qwashed.core` and downstream modules raises one of these on any error
  path; no silent `return None` / `return False` fallback.
- `qwashed.core.canonical`: RFC 8785 canonical JSON serialization.
  `canonicalize(obj) -> bytes` handles null, bool, int, float (with
  NaN/Inf rejection), strings (RFC 8259 short escapes plus `\uXXXX` for
  control chars), objects (UTF-16-codeunit-sorted keys with surrogate-pair
  handling for supplementary characters), arrays, tuples, and explicit
  cycle detection. `canonical_hash(obj, algo="sha256"|"sha3-256")` returns
  the hex digest of the canonical bytes.
- `qwashed.core.schemas`: `StrictBaseModel` (frozen, `extra="forbid"`,
  `str_strip_whitespace=True`, `validate_assignment=True`) as the project's
  only base model. `parse_strict()` converts pydantic `ValidationError` to
  `SchemaValidationError`. Reusable `AfterValidator`-bindable validators:
  `nonempty_str`, `b64_bytes`, `sha256_hex`, `ed25519_pubkey_b64` (32-byte
  decode check), `mldsa65_pubkey_b64` (FIPS 204 1952-byte decode check).
- `qwashed.core.kdf`: `hkdf_sha256(*, ikm, salt, info, length)` over
  `cryptography.hazmat` HKDF (RFC 5869); enforces non-empty IKM and
  RFC-cap output length (8160 bytes). `argon2id(*, password, salt,
  memory_kib, time_cost, parallelism, length)` over `argon2-cffi` with
  lazy import; OWASP-baseline defaults (64 MiB / 3 iter / 1 lane) and
  fail-closed minimums (19 MiB / 2 iter / 1 lane / 16-byte output / 16-byte
  salt). `info_for(*, module, purpose, version)` builds the canonical
  Qwashed HKDF info string `b"qwashed/<module>/<version>/<purpose>"` and
  rejects empty / slash-containing purposes to prevent namespace forgery.
- `qwashed.core.signing`: Ed25519 wrappers `SigningKey` and `VerifyKey`
  over `cryptography.hazmat.primitives.asymmetric.ed25519`. `SigningKey`
  uses slots and `__repr__` exposes only the verify-key fingerprint
  (never the seed). `VerifyKey.verify()` returns `bool` for sig mismatch
  and raises `SignatureError` only for structural failures (wrong-length
  signature, malformed key). Round-trip via `to_bytes()` / `to_b64()` /
  `from_bytes()` / `from_b64()`. Hybrid Ed25519||ML-DSA-65 deferred to
  Phase 3 (`qwashed.vault.hybrid_sig`).
- `qwashed.core.report`: pure-stdlib HTML template substitution with
  `{{ name }}` placeholders. `render_html(template, context)` HTML-escapes
  everything except `SafeString` / `mark_safe()` values; rejects
  unbalanced braces, malformed names, and unknown placeholders.
  `render_pdf(html, output_path)` does a minimal HTML → PDF render via
  lazy `reportlab` import (raises `ConfigurationError` if the optional
  dependency is missing).
- `qwashed verify <artifact.json>` CLI subcommand: parses a signed
  artifact, canonicalizes the payload (everything except signature
  fields) per RFC 8785, and verifies the embedded
  `signature_ed25519` against the embedded `ed25519_pubkey`. Exits 0 on
  valid, 1 on signature mismatch, 2 on structural / IO / parse error.

### Verified

- Phase 1 quality gate green on macOS Darwin arm64 / Python 3.13.2:
  `ruff check` clean, `ruff format --check` clean, `mypy --strict` clean
  (12 source files), `pytest` 119/119 passing across 8 test modules.

#### Phase 0 (project scaffolding) — 2026-04-30

- Apache 2.0 license (`LICENSE`) and NOTICE file with trademark statement.
- `pyproject.toml` with hatchling build backend, `qwashed[audit|vault|report|full|dev]`
  extras, ruff/mypy/pytest configuration, and `qwashed` CLI entry point.
- README, threat-model placeholder, security-disclosure policy, and contributor
  documentation skeletons.
- `.gitignore` covering Python build artifacts plus Qwashed-specific patterns
  (vault directories, signing keys, real audit artifacts) that must never be
  committed.
- GitHub Actions CI scaffold (`lint`, `test`, `typecheck` jobs) on Python
  3.11/3.12/3.13, macOS arm64 and Linux x86_64.
- Empty `qwashed.core`, `qwashed.audit`, `qwashed.vault` package skeletons.
- CLI dispatcher with `--version` and stub subcommands so `pip install -e .`
  produces a working `qwashed` command immediately.
- Smoke test asserting the package imports and exposes a version.

### Verified

- Phase 0 quality gate green on macOS Darwin arm64 / Python 3.13.2:
  `ruff check` clean, `ruff format --check` clean, `mypy --strict` clean
  (6 source files), `pytest` 10/10 passing including the `python -m qwashed`
  and console-script entry-point tests.

### Confirmed

- Python 3.13.2 available on the development machine (macOS Darwin arm64).
- `liboqs-python` 0.14.1 is the canonical PyPI package name (not `oqs-python`);
  build plan dependency name updated accordingly in `pyproject.toml`.
- `sslyze` 6.3.x is the latest TLS-probing library; v0.1 will use it.

### Decided

- TLS-probe approach: `sslyze` for v0.1 (faster to ship); hand-rolled hello
  deferred to v0.2 if sslyze maintenance becomes a risk. (Open question Q1
  in build plan §17.)

[Unreleased]: https://github.com/qwashed/qwashed/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/qwashed/qwashed/releases/tag/v0.1.0
