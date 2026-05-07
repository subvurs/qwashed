# Qwashed Roadmap

**Status:** authoritative roadmap as of 2026-05-06.
**Supersedes** scattered v0.2 references in `QWASHED_BUILD_PLAN.txt` §16,
`README.md` §"Where Qwashed is *not* the right tool", `docs/SECURITY.md`,
`THREAT_MODEL.md` §"Versioning and forward compatibility", and the
`v0.2` deferral comment in `qwashed/audit/scoring.py`.

This document is the single source of truth for what is planned, what is
deferred, and what each work item entails. When other docs disagree with
this roadmap, this roadmap wins; the conflicting doc should be updated.

---

## 1. Where v0.1.0 left things

Released 2026-04-30. The shipped surface:

- `qwashed.core` — RFC 8785 canonical JSON, Ed25519 signing, HKDF-SHA256,
  Argon2id, strict pydantic schemas, typed error hierarchy.
- `qwashed.audit` — TLS + SSH HNDL probes (sslyze + stdlib + static),
  classifier, scoring, migration roadmap, signed JSON / HTML / PDF
  reports, four bundled threat profiles, deterministic mode, golden tests.
- `qwashed.vault` — hybrid X25519 || ML-KEM-768 KEM, hybrid Ed25519 ||
  ML-DSA-65 signing, SHA3-256 hash-chained signed audit log, file vault
  with put / get / list / verify / export / recipients, full CLI.
- 418 passing tests, mypy --strict clean, FIPS 203 / 204 KAT vectors enforced.
- Apache-2.0, GitHub release signed with the project Ed25519 key.

Known v0.1 limits (carried forward as v0.2 inputs):

- Probe coverage is TLS + SSH only. No SMTP STARTTLS, IMAPS, MQTT,
  WireGuard, IPsec, PGP, S/MIME.
- Release-signing is classical Ed25519 only — the auditor and vault
  artifacts use hybrid Ed25519 || ML-DSA-65, but the *release* artifact
  does not.
- Vulnerability disclosure has only one encrypted channel (age). No GPG
  identity is published.
- Vault format and HKDF info strings are pinned at `qwashed/vault/v0.1/*`;
  there is no migration path from v0.1 to a future v0.2 vault format.
- Scoring uses the simplest defensible formula:
  `score = category_weight × archival_likelihood`. Cipher strength,
  certificate lifetime, and key-length effects are deferred.
- Threshold / M-of-N decryption is not implemented (age plugins fill this
  gap for non-PQ users).
- No GUI, no localization, no hardware-token support.

---

## 2. v0.2 goals

v0.2 is a **breadth + hardening** release, not a new-product release. The
core shape (HNDL audit + hybrid PQ vault) is stable; v0.2 widens probe
coverage, closes the release-signing asymmetry, hardens the disclosure
channels, opens a migration path to a future vault format, and makes
the scoring richer without inventing new cryptography.

**v0.2 explicitly does NOT include:**

- GUI (deferred to v0.3).
- Multi-recipient / threshold vault unsealing as a vault primitive
  (deferred to v0.3 as `group vault`). v0.2 *does* close the README's
  ambiguity about this — see §6 reconciliation.
- Hardware-token (YubiKey, OnlyKey) integration (v0.3).
- Localization / i18n (v0.3).
- Third-party security audit (v1.0).
- Trademark registration (v1.0).
- Stable algorithm tables / frozen schema (v1.0).

---

## 3. v0.2 work items

Each item lists **scope**, **files touched**, **dependencies**, **risk**,
**done means**. Complexity tag: **S** = small (single module, well-bounded),
**M** = medium (multiple modules + new tests), **L** = large (new subsystem,
new external dependency, or threat-model implications).

### 3.1 — Hybrid release signing  **L**

**Why:** v0.1's release artifact is signed with classical Ed25519 only.
Every other Qwashed-emitted artifact (audit reports, vault entries, audit
log) is hybrid Ed25519 || ML-DSA-65. The release artifact is the highest-
value forgery target (ship a malicious wheel and own everyone's vaults),
so the asymmetry is the wrong way around.

**Scope:**

- Generate a v2 release-signing key bundle: Ed25519 + ML-DSA-65,
  fingerprint = first 16 hex of `SHA-256(ed25519_pub || mldsa65_pub)`.
- Add a `release_keys/qwashed-release-v2.pub` bundle file (already-supported
  format from `qwashed.vault.hybrid_sig.HybridVerifyKey.to_b64()`).
- Sign `SHA256SUMS` with both halves; ship as `SHA256SUMS.sig` (Ed25519)
  and `SHA256SUMS.sig.pq` (ML-DSA-65), or as a single combined hybrid sig
  envelope. Combined envelope is preferred for parity with the vault.
- Extend `qwashed verify` (already in core CLI) to verify hybrid release
  signatures, fail-closed on either component.
- Update `docs/VERIFY_RELEASE.md` with hybrid-verification flow,
  air-gapped install steps, and key-rotation announcement format.
- Cross-sign: announce v2 key in CHANGELOG signed by the v0.1 release key
  before retiring it (pinning continuity).

**Files touched:**
`release_keys/`, `qwashed/cli.py` (verify subcommand),
`qwashed/vault/hybrid_sig.py` (already exists, may need a release-context
helper), `docs/VERIFY_RELEASE.md`, `docs/SECURITY.md` (publish v2 fingerprint),
`RELEASE_HANDOFF.md` (replace v0.1 key generation with v2).

**Dependencies:** none — uses existing hybrid_sig module.

**Risk:** key-rotation procedure is the dangerous part. A typo in the
cross-signed CHANGELOG announcement leaves users unable to verify v0.2.
Mitigation: dry-run the rotation against a throwaway repo before doing
it for real, and write the rotation as a script in `RELEASE_HANDOFF.md`
not freehand.

**Done means:**
- v0.2.0 release artifact verifies under hybrid release verification.
- Tampering with either signature component fails verification.
- v0.1 → v0.2 key-rotation announcement is itself v0.1-signed and
  reproducible from `--deterministic`-mode tooling.

---

### 3.2 — Email PGP / S/MIME audit probe  **M**  ✅ **LANDED 2026-05-06**

**Why:** Civil-society correspondents heavily rely on PGP and (less so)
S/MIME. These are the lowest-hanging probe to add, and they fit the
existing `Probe` ABC cleanly.

**Status (2026-05-06):** Landed. Deviations from the original scope:
- PGP parsing is **hand-rolled** (`qwashed/audit/probe_pgp.py`), not
  `pgpy`. Rationale: `pgpy` is under-maintained, and the v0.2 surface
  only needs primary-public-key classification (RFC 4880 §5.5) — a
  ~150-LOC parser keeps the dependency surface flat. Subkeys are skipped
  to find the primary; user-IDs are not parsed.
- S/MIME uses `cryptography.x509` (already a Qwashed dep for Ed25519
  signing) — no new dependency.
- New `MultiplexProbe` routes per-protocol; the CLI's `--probe`
  selector now controls only the TLS slot. PGP / S/MIME slots are
  always wired.
- `AuditTarget.protocol` extended with `pgp`, `smime`; new
  `FILE_ONLY_PROTOCOLS = {"pgp", "smime"}` set; new `key_path` field
  with model-validator enforcement.
- Relative `key_path` in YAML configs resolves against the config
  file's directory so audit bundles can ship `keys/` alongside
  `email_pgp.yaml`.
- Tests: 23 PGP probe tests (hand-rolled OpenPGP packet builders),
  21 SMIME probe tests (in-memory cryptography fixtures), +8
  classifier cases, +9 roadmap cases, golden files regenerated for
  the updated non-OK status text.
- Examples: `examples/audit/email_pgp.yaml`,
  `examples/audit/email_smime.yaml`.
- Total `tests/audit/` count: 225 passing (1 sslyze conditional skip).
- Scope honored: keyring / WKD / HKP discovery deferred to v0.3
  ("public-key-blob input only" as documented in the original
  Risk section).

**Scope:**

- `qwashed.audit.probe.PgpProbe`: parses a PGP public key (binary or
  ASCII-armor) supplied as a target file, classifies the primary key
  algorithm + size, and reports HNDL exposure exactly the same way as a
  TLS finding (classical / hybrid_pq / pq_only / unknown).
- `qwashed.audit.probe.SmimeProbe`: parses an S/MIME certificate (X.509
  PEM / DER), classifies the signature + KEM algorithm.
- Extend `AuditTarget.protocol` enum: add `pgp`, `smime`. Update the
  config YAML schema and the four bundled example configs.
- Extend `qwashed.audit.algorithm_tables` JSON with PGP key-algorithm
  identifiers (RSA-2048/3072/4096, ECDSA-P256/P384, Ed25519, Curve25519,
  ML-KEM-* if/when OpenPGP adopts it).
- Add fixtures + golden tests under `tests/audit/`.

**Files touched:**
`qwashed/audit/probe.py`, `qwashed/audit/schemas.py`,
`qwashed/audit/algorithm_tables/`, `qwashed/audit/cli.py` (no schema
changes; the YAML loader will pick up the new enum), `examples/audit/`,
`tests/audit/test_probe.py`, `tests/audit/fixtures/`.

**Dependencies:** PGP key parsing — prefer `pgpy` for pure-Python without
GnuPG dependency; fall back to `cryptography`'s OpenSSL bindings for
S/MIME X.509. **No call out to `gpg`** — that would violate the
no-network-no-subprocess invariant. If PGP parsing requires a binary
shell-out, defer to v0.3.

**Risk:** OpenPGP message format is genuinely complex and `pgpy` is
under-maintained. If `pgpy` integration becomes painful, document
"public-key-blob input only, RFC 4880 §5.5" as the v0.2 scope and defer
keyring / WKD / HKP discovery to v0.3.

**Done means:**
- `qwashed audit run` accepts `protocol: pgp` and `protocol: smime`
  targets pointing at local key files.
- Misclassification tests cover the obvious confusions (PGP RSA-1024 →
  classical+critical; PGP Ed25519 → classical+high; PGP ML-KEM-aware
  hybrid → hybrid_pq+low).
- HTML report renders PGP/S/MIME findings with the same severity
  colour-coding as TLS/SSH.

---

### 3.3 — WireGuard / IPsec endpoint probing  **L**

**Why:** Civil-society orgs that have done OpSec basics generally use
WireGuard or IPsec for site-to-site or remote access. These are
post-quantum-naïve out of the box (X25519 + ChaCha20-Poly1305 for WG;
many IPsec deployments use RSA-2048 IKE).

**Scope:**

- `qwashed.audit.probe.WireGuardProbe`: parses a WireGuard config
  (`wg-quick` format or `wg show`-style key dump) supplied as a target
  file or text blob. Classifies as classical (WG v1, no PQ extension)
  unless the deployment uses the hybrid-PQ WireGuard variant (Rosenpass
  or similar) — detected by config sentinel.
- `qwashed.audit.probe.IpsecProbe`: parses an `ipsec.conf` /
  `swanctl.conf` or queries an IKE responder over UDP/500 with a
  read-only IKE_SA_INIT to enumerate proposed Diffie-Hellman groups,
  encryption, and PRF. Classify against algorithm_tables.
- IKE probe must be **opt-in** (a flag in the YAML target) because it
  sends a packet to a remote host. The PGP/S-MIME and WG-config probes
  are file-only and need no opt-in.
- Extend `AuditTarget.protocol` enum: `wireguard`, `ipsec`.

**Files touched:**
`qwashed/audit/probe.py`, `qwashed/audit/schemas.py`,
`qwashed/audit/algorithm_tables/`, `qwashed/audit/cli.py`,
`examples/audit/`, `tests/audit/test_probe.py`, fixtures with synthetic
`wg0.conf` and `ipsec.conf` examples.

**Dependencies:** IKE handshake parsing. Use `scapy` for the UDP/500
IKE_SA_INIT packet construction (lazy import; only required if the
WG/IPsec extras are installed). Add `qwashed[network]` extras for
`scapy`.

**Risk:** IKE active probing is the first time Qwashed sends a packet
that is not a TLS handshake. Reviewers may flag this as scope creep
("Qwashed is supposed to be hygiene, not a scanner"). Mitigation:
require an explicit `--allow-active-network-probe` flag on the CLI
*and* an explicit per-target `active_probe: true` in YAML, both of
which default to off. Document the policy in `docs/AUDIT_GUIDE.md`.

**Done means:**
- WG-config-only audit works fully offline against an RFC-1918 fixture.
- IPsec opt-in IKE probe completes against an `ipsec-tools` test
  responder in CI; default-off in user-facing CLI.
- Both produce findings + roadmap items in the existing severity
  framework.

---

### 3.4 — Hand-rolled TLS probe  **M**  ✅ **LANDED 2026-05-06**

**Why:** v0.1 took the explicit decision to use sslyze 6.3.x to ship
faster (BUILD_PLAN §17 Q1). The deferred risk was sslyze maintenance.
v0.2 closes that risk by reimplementing the minimal hello we need.

**Scope:**

- `qwashed.audit.probe.NativeTlsProbe`: opens a TCP connection, sends a
  TLS 1.3 (and 1.2-fallback) ClientHello with the cipher-suite,
  signature-algorithm, and supported-groups extensions Qwashed cares
  about, parses the ServerHello + Certificate, and emits a
  `ProbeResult`.
- Pure stdlib + `cryptography` for the X.509 parse. **No** new
  dependency.
- Wire-format parsing only. No alert-driven-fingerprinting tricks; no
  exploit code; no JA3-class fingerprinting. We are reading what the
  server volunteers, not testing what it permits.
- Becomes the default; sslyze becomes opt-in via `qwashed[audit-deep]`
  extras for users who want sslyze's deeper enumeration.

**Files touched:**
`qwashed/audit/probe.py` (new `NativeTlsProbe` class),
`qwashed/audit/cli.py` (probe-implementation selector),
`pyproject.toml` (move sslyze under `[audit-deep]` extras),
`tests/audit/test_probe.py` (new fixtures using a stdlib TLS server).

**Dependencies:** none new.

**Risk:** wire-format TLS parsers grow legs. Mitigation: bound the
parser to TLS 1.2 + 1.3, refuse TLS 1.0 / 1.1 / SSLv3 server responses
with a clear `ProbeResult.status = "tls_version_unsupported"`, and
property-test against `cryptography.hazmat`'s test vectors.

**Done means:**
- Default TLS probe in v0.2 is `NativeTlsProbe`. ✅
- All v0.1 golden tests continue to pass. ✅
- A user can `pip install qwashed` (no extras) and run a TLS audit
  without sslyze installed. ✅

**Implementation summary (landed 2026-05-06):**

- `qwashed/audit/_tls_wire.py` (NEW, internal): self-contained TLS 1.2
  / 1.3 wire-format helpers built on `cryptography`'s primitives only —
  no `ssl`-module reliance, no third-party TLS library:
  - Record / handshake / extension type constants per RFC 8446 +
    RFC 5246; `TLS_1_2` / `TLS_1_3` legacy/protocol versions; the
    fixed HelloRetryRequest SHA-256 `random` per §4.1.4.
  - `build_client_hello(hostname, ...)` → `(client_hello_bytes,
    material)` with deterministic extensions: `supported_versions`
    (TLS 1.2 + 1.3), `signature_algorithms` (Ed25519, ML-DSA OIDs,
    ECDSA, RSA-PSS), `supported_groups` (X25519, X25519MLKEM768
    codepoint `0x11EC` per draft-kwiatkowski-tls-ecdhe-mlkem, P-256,
    P-384), and a fresh X25519 `key_share`. SNI omitted for IP
    literals (RFC 6066) and empty hostnames.
  - `HandshakeReader` reassembles handshake messages across record
    fragments without buffering the whole transcript.
  - `parse_server_hello`, `parse_extensions`, `parse_certificate`,
    `parse_server_key_exchange_named_curve` return typed dataclasses
    (`ServerHelloFields`, etc.); HelloRetryRequest detected via the
    fixed `random`.
  - `cert_signature_algorithm_friendly_name(cert)` maps X.509 OIDs to
    short names (`ed25519`, `id-ml-dsa-65`, `sha256WithRSAEncryption`,
    …); unknown OIDs render as `oid:1.2.3.4` with no false-confidence
    label.
  - `derive_tls13_server_handshake_keys(...)`: full RFC 8446 §7.1 key
    schedule (HKDF-Extract / Derive-Secret / HKDF-Expand-Label) over a
    transcript hash, returning AES-128-GCM-SHA256 / AES-256-GCM-SHA384
    server handshake key + IV.
  - `friendly_kex_name`, `friendly_cipher_suite_name` for finding
    labels.
  - `TlsWireError` typed parsing failure (length-prefix overflow,
    truncated record, unknown extension structure) — always surfaces
    as `ProbeResult.status="handshake_failed"`.
- `qwashed/audit/probe.py`:
  - New `NativeTlsProbe` implementing the `Probe` ABC. `probe(target)`
    rejects non-TLS protocols, opens a TCP socket at the configured
    timeout, calls `_handshake()` which builds a ClientHello via
    `_w.build_client_hello`, sends it, reads ServerHello via
    `_w.HandshakeReader`, and branches:
    - TLS 1.3 → `_finish_tls13(...)`: validates the X25519 key_share,
      computes ECDHE via `material.x25519_priv.exchange(peer_pub)`,
      derives server handshake keys via
      `_w.derive_tls13_server_handshake_keys` over the transcript
      hash, decrypts subsequent records with AES-GCM (RFC 8446 §5.4
      trailing-zero stripping), skips ChangeCipherSpec, parses the
      Certificate handshake message for signature-algorithm
      classification.
    - TLS 1.2 → `_finish_tls12(...)`: reads cleartext records,
      processes Certificate + ServerKeyExchange + ServerHelloDone,
      classifies the named curve from ServerKeyExchange.
    - HelloRetryRequest, SSLv3 / TLS 1.0 / 1.1, and any
      `TlsWireError` / `OSError` / `TimeoutError` rejected
      fail-closed with typed `error_detail`.
  - `_format_tls_version(version)` helper: `TLS_1_3 → "TLSv1.3"`,
    `TLS_1_2 → "TLSv1.2"`, `None` for older versions.
  - `NativeTlsProbe` exposed on `__all__`.
  - `probe_target(...)` default flipped from `SslyzeTlsProbe()` to
    `NativeTlsProbe()`.
- `qwashed/audit/cli.py`:
  - New `_probe_for_args(args) -> Probe` dispatcher reading
    `args.probe` (`{native, stdlib, sslyze}`, default `native`) and
    `args.probe_timeout` (default `DEFAULT_TIMEOUT_SECONDS`). Unknown
    selectors raise `ConfigurationError`.
  - `_audit_run` now passes `probe_impl=_probe_for_args(args)` to
    `run_audit`.
  - `audit run` argparse adds `--probe` and `--probe-timeout` flags.
- `pyproject.toml`: `[audit]` extras split:
  - `audit-deep = ["sslyze>=6.0"]`
  - `audit-ssh = ["paramiko>=3.4"]`
  - `audit = ["qwashed[audit-deep,audit-ssh]"]` (meta-extra preserved
    as v0.1 upgrade alias)
  - Comment block explaining that the default TLS probe
    (`NativeTlsProbe`) is hand-rolled on top of the always-installed
    `cryptography` core dependency, so a no-extras install can run a
    full PQ-posture audit out of the box.
- `tests/audit/test_probe.py` (+22 new tests, 7 classes):
  - `TestNativeTlsProbe` (6) — round-trip against the loopback TLS
    fixture, unreachable port, DNS failure, SSH target rejection,
    invalid timeout, non-TLS garbage rejection.
  - `TestTlsWireSni` (5) — IP literals / empty / non-ASCII hostname
    handling.
  - `TestHandshakeReader` (3) — single / fragmented / multi-message
    feeds.
  - `TestParseServerHello` (1) — too-short body raises
    `TlsWireError`.
  - `TestCertSigAlgoFriendlyName` (4) — known OIDs (RSA, Ed25519,
    ML-DSA-65) and unknown OID fallback.
  - `TestBuildClientHello` (2) — record header validity, SNI omitted
    for IP literals.
  - `TestProbeTargetDefault` (1) — default codepath through
    `probe_target(...)`.
- `docs/AUDIT_GUIDE.md`: new "Choosing a TLS probe backend" section
  with the install-extras matrix and per-backend rationale.

**Verification:**
- 460 tests pass (was 438 after §3.6: +22 §3.4 tests).
- 1 pre-existing sslyze-conditional skip (unchanged; `[audit-deep]`
  keeps the install path optional).
- `mypy --strict qwashed/` clean across 28 source files. Hash-class
  name mypy gotcha resolved by storing `("sha256", 16)` /
  `("sha384", 32)` as explicit strings in
  `_tls_wire.TLS13_CIPHER_PARAMS` rather than relying on
  `cryptography.hashes.SHA256.name`'s descriptor.
- `ruff check .` and `ruff format --check .` clean.
- Backward compatibility: `StdlibTlsProbe` and `SslyzeTlsProbe`
  codepaths unchanged; v0.1 golden audit fixtures still
  byte-identical under `--deterministic`.

---

### 3.5 — Richer HNDL scoring  **S**  ✅ **LANDED 2026-05-06**

**Why:** `qwashed/audit/scoring.py:22` defers cipher strength,
certificate lifetime, and key length to v0.2.

**Scope:**

- Extend `score_finding` to incorporate:
  - **Key length penalty:** RSA < 2048 → boost score by `+0.10`,
    RSA < 3072 → `+0.05`, ECC < 224 bit → `+0.05`. Bounded so the score
    stays in `[0, 1]`.
  - **Certificate lifetime:** TLS leaf cert with NotAfter > 2030-01-01
    → boost by `+0.05` (more time for HNDL adversary to harvest).
  - **Optional cipher AEAD strength:** non-AEAD cipher (CBC-mode) in TLS
    response → boost by `+0.05`.
- Each contribution must be documented per-finding in `rationale` so the
  user can see *why* the score shifted.
- Threat-profile YAML gains optional `key_length_thresholds` /
  `cert_lifetime_horizon` keys with safe defaults; existing v0.1
  profiles continue to work unchanged.

**Files touched:**
`qwashed/audit/scoring.py`, `qwashed/audit/schemas.py` (ThreatProfile
extension), `qwashed/audit/profiles/*.yaml`,
`tests/audit/test_scoring.py`, `tests/audit/test_golden.py` (regenerate
goldens with documented diff).

**Dependencies:** none.

**Risk:** "easy to overweight" — the v0.1 comment was correct. Bound
each contribution to `+0.10` max, sum to `+0.20` max, and add a
property test asserting the score never moves more than 0.20 below or
above the v0.1 baseline for the same probe.

**Done means:**
- v0.2 scoring on the v0.1 golden fixtures shifts in the documented
  direction, by no more than the bounded amount.
- New `--explain` CLI flag prints the per-contribution breakdown.

**Implementation summary (landed 2026-05-06):**

- `qwashed/audit/scoring.py`:
  - Module-level v0.2 boost catalog: `_KEY_LENGTH_RSA_WEAK_BOOST=0.10`,
    `_KEY_LENGTH_RSA_BELOW_STRONG_BOOST=0.05`,
    `_KEY_LENGTH_ECC_WEAK_BOOST=0.05`,
    `_CERT_LIFETIME_PAST_HORIZON_BOOST=0.05`,
    `_CIPHER_NON_AEAD_BOOST=0.05`.
  - Per-arm cap `_BOOST_PER_CONTRIBUTION_CAP=0.10`, total cap
    `_BOOST_TOTAL_CAP=0.20`. When the unclamped sum exceeds the total
    cap, contributions are scaled proportionally so each individual
    rationale line stays ≤ its declared boost weight.
  - Default thresholds (`_DEFAULT_RSA_MINIMUM=2048`,
    `_DEFAULT_RSA_STRONG=3072`, `_DEFAULT_ECC_MINIMUM=224`) and default
    `_DEFAULT_CERT_LIFETIME_HORIZON="2030-01-01"` (ISO YYYY-MM-DD,
    lexicographic-safe).
  - Resolver helpers `_resolve_rsa_minimum`, `_resolve_rsa_strong`,
    `_resolve_ecc_minimum`, `_resolve_cert_lifetime_horizon` consume the
    threat-profile `key_length_thresholds` / `cert_lifetime_horizon`
    keys and fall back to defaults.
  - `_compute_v02_boosts(probe, profile)` returns a list of `(label,
    boost, message)` tuples plus the proportionally clamped sum,
    documented per-contribution in `rationale`.
  - `score_finding(...)` sums `category_score + v02_boost` then clamps
    to `[0.0, 1.0]`. v0.1 fixtures are byte-identical when no probe
    fields trigger boosts.
  - New `explain_finding(finding, profile)` helper renders a
    multi-line per-finding breakdown for `--explain`.
- `qwashed/audit/schemas.py`:
  - `ProbeResult` gains `public_key_bits: Optional[int]`,
    `public_key_algorithm_family: Optional[str]`,
    `cert_not_after: Optional[str]` (ISO YYYY-MM-DD),
    `aead: Optional[bool]`. All optional, all default `None`, so v0.1
    probes that don't populate them keep the v0.1 score.
  - `ThreatProfile` gains optional `key_length_thresholds: dict`,
    `cert_lifetime_horizon: str`, `enable_v02_scoring: bool = True`.
    The opt-out lets a v0.1-pinned profile reproduce 2026-05-05 scores.
- `qwashed/audit/_tls_wire.py`: `CertificateInfo` extended with
  `public_key_bits` (RSA modulus bit length, EC curve key size, 0 for
  Ed25519/Ed448), `public_key_family` (`"rsa" | "ec" | "dsa" | ""`),
  and `not_valid_after_iso` (ISO YYYY-MM-DD via the
  cryptography>=42 `not_valid_after_utc` accessor).
- `qwashed/audit/probe.py`: `StdlibTlsProbe` and `NativeTlsProbe` thread
  the new fields into `ProbeResult`. AEAD detection: TLS 1.3 always
  AEAD; TLS 1.2 AEAD iff cipher name contains `GCM`, `CHACHA20`, or
  `CCM`.
- `qwashed/audit/probe_smime.py`: `SmimeCertInfo` and `SmimeProbe`
  populate `public_key_bits` (RSA modulus, EC curve key size) and
  `public_key_algorithm_family` (`"rsa" | "ec" | "dsa"`).
- `qwashed/audit/probe_pgp.py`: `PgpKeyInfo` gains `family` field;
  `_classify_algorithm` populates it for every supported algorithm
  arm; `PgpProbe.probe` threads `public_key_bits` /
  `public_key_algorithm_family` into the `ProbeResult`.
- `qwashed/audit/cli.py`: new `--explain` flag prints per-finding boost
  breakdown to stderr after the report renders, using
  `explain_finding(...)` so the same logic powers the score and the
  human-readable explanation.
- `tests/audit/test_scoring.py`: 18 new tests covering each individual
  boost, the +0.10 per-arm cap, the +0.20 total cap, score clamping
  at 1.0, threshold/horizon overrides, and `enable_v02_scoring=False`
  reproducing v0.1 scores. Plus a Hypothesis property test sweeping
  category × bits × not_after × aead × family that asserts the boost
  envelope: `0.0 ≤ boost ≤ 0.20` and `score ∈ [0.0, 1.0]`.
- `tests/audit/test_golden.py`: canned-probe builders extended with
  `public_key_bits`, `public_key_algorithm_family`, `cert_not_after`,
  `aead`. All four golden files
  (`civic_default.json`, `healthcare_healthcare.json`,
  `journalism_journalism.json`, `legal_legal.json`) regenerated and
  byte-stable across runs.

**Verified:**

- `pytest tests/audit/` → 245 passed.
- `pytest tests/` → 543 passed, 1 skipped (pre-existing sslyze
  conditional skip).
- v0.1-pinned profile (`enable_v02_scoring=False`) reproduces the
  pre-v0.2 golden scores exactly.

---

### 3.6 — Vault format v0.2 (migration path)  **M**  ✅ **LANDED 2026-05-05**

**Why:** `THREAT_MODEL.md` §"Versioning and forward compatibility"
commits to a `qwashed/vault/v0.2/*` HKDF info string and a
`qwashed vault upgrade` re-encryption path. This is the v0.2 release
that creates the precedent.

**Scope:**

- Bump HKDF info string for new vaults to `qwashed/vault/v0.2/kem` and
  `qwashed/vault/v0.2/entry-aead`.
- Vault on-disk format gains a `format_version` field in `manifest.json`
  and in each entry's `meta.json`. v0.1 = `1`, v0.2 = `2`.
- `qwashed vault upgrade [--root PATH]` CLI subcommand: reads each v0.1
  entry, decrypts with v0.1 HKDF info, re-encrypts with v0.2 HKDF info,
  writes a v0.2 entry, atomically swaps, appends an upgrade record to
  the audit log. **No plaintext spill** — re-encryption happens in
  memory only.
- v0.2 readers MUST still read v0.1 entries until the v0.4 deprecation
  window expires (one major-version after the introduction was the
  THREAT_MODEL commitment).
- Add `tests/vault/test_format_migration.py`: round-trip a v0.1 vault
  through `vault upgrade`, assert all entries verify against the v0.2
  format, audit log shows upgrade events for each entry.

**Files touched:**
`qwashed/vault/store.py`, `qwashed/vault/hybrid_kem.py` (info string
parameter — already parameterized), `qwashed/vault/cli.py`,
`qwashed/vault/audit_log.py` (new `"upgrade"` op), `qwashed/vault/__init__.py`,
`tests/vault/test_format_migration.py`,
`docs/VAULT_GUIDE.md` (migration section — pending).

**Dependencies:** the algorithm choice for v0.2 stays X25519 ||
ML-KEM-768 (no algorithm change in v0.2). The format bump exists to
exercise the migration machinery before there's an emergency reason
to use it.

**Risk:** plaintext-spill during re-encryption. Mitigation: re-encrypt
in a temp buffer, atomically rename only when the new entry verifies,
never write plaintext to disk, scrub the buffer with `bytearray(...)`
overwrite-and-zero before deallocation.

**Done means:**
- `qwashed vault upgrade` round-trips a v0.1 vault to v0.2 with
  bytes-identical retrieval afterwards. ✅
- v0.2 readers read both v0.1 and v0.2 entries. ✅
- Audit log shows one signed upgrade event per entry. ✅

**Implementation summary (landed 2026-05-05):**

- `qwashed/vault/store.py`:
  - New format-version constants: `FORMAT_VERSION_V01=1`, `FORMAT_VERSION_V02=2`,
    `FORMAT_VERSION_CURRENT=2`, `_SUPPORTED_FORMAT_VERSIONS={1,2}`.
  - New blob-version byte constants: `BLOB_VERSION_V01`, `BLOB_VERSION_V02`,
    `BLOB_VERSION` (= V02). The 5th byte of every entry blob is now the
    on-disk format version, used as the dispatch discriminator at decode.
  - New entry-AEAD info constants: `ENTRY_AEAD_INFO_V01` (`qwashed/vault/v0.1/entry-aead`),
    `ENTRY_AEAD_INFO_V02` (`qwashed/vault/v0.2/entry-aead`), and
    `_entry_aead_info_for(format_version)` dispatcher.
  - `VaultManifest` and `EntryMetadata` dataclasses gain
    `format_version: int = FORMAT_VERSION_V01`. The field is omitted from
    the canonical-JSON body when `== 1`, preserving v0.1 byte-identical signatures.
  - `_seal_blob(..., format_version=FORMAT_VERSION_CURRENT)` threads the
    target format through `encapsulate(...)` and `_entry_aead_info_for(...)`,
    writing the correct blob-version byte.
  - `_open_blob(...)` reads the blob-version byte, validates against
    `_SUPPORTED_FORMAT_VERSIONS`, and dispatches `decapsulate(format_version=...)`
    + `_entry_aead_info_for(...)` accordingly.
  - New `_peek_blob_version(blob_bytes)` helper reads on-disk format
    without decrypting (used by `Vault.upgrade` for fast skip-already-current).
  - Sign/verify/parse helpers for manifest + metadata
    (`_sign_manifest`/`_verify_manifest`/`_parse_manifest`,
    `_sign_metadata`/`_verify_metadata`/`_parse_metadata`) widened to
    thread and validate `format_version`.
  - New `UpgradeReport` frozen dataclass: `(upgraded, already_current,
    target_format_version)`.
  - New `Vault.upgrade(*, target_format_version=FORMAT_VERSION_CURRENT)`
    method:
    1. Snapshot entry list via `self.list()`.
    2. For each entry: peek blob version; skip if already at target.
    3. Cross-check `meta.format_version == blob_version` (fail-closed
      with `SignatureError` on mismatch — defends against forged
      meta-vs-blob version skew).
    4. Decrypt into a `bytearray` (mutable, scrubbable).
    5. Re-seal at `target_format_version`.
    6. Atomic-write new blob, then new meta.
    7. Append `"upgrade"` audit-log line (signed, hash-chained).
    8. Zero the plaintext bytearray in `finally` before any disk I/O.
    9. Rewrite manifest at `target_format_version` only if anything changed
      (idempotent no-op for already-current vaults).
- `qwashed/vault/hybrid_kem.py`:
  - `HYBRID_KEM_INFO_V01`, `HYBRID_KEM_INFO_V02` constants;
    `kem_info_for_format(format_version)` helper.
  - `format_version` parameter threaded through `_combine`,
    `encapsulate`, `decapsulate`.
- `qwashed/vault/audit_log.py`:
  - `"upgrade"` added to `OPS` frozenset and the `Op` Literal type so
    upgrade events are first-class audit-log entries (signed + chained).
- `qwashed/vault/cli.py`:
  - New `qwashed vault upgrade [--path PATH]` subparser and `_vault_upgrade`
    handler. Exits 1 on `SignatureError`, 2 on other `QwashedError`,
    0 on success. Prints upgraded / already-current counts and target
    format version.
- `tests/vault/test_format_migration.py` (NEW, 21 tests, 7 classes):
  - `TestNewVaultIsV02` — fresh vaults write manifest + entries at v0.2.
  - `TestV01ReadableByV02Reader` — legacy entries readable by v0.2 reader;
    v0.1 manifest + meta omit the `format_version` field entirely.
  - `TestUpgrade` — full migration round-trip; plaintext byte-identical
    pre/post upgrade; idempotent (second upgrade is a no-op); audit log
    shows one `"upgrade"` line per entry; original `"put"` lines preserved;
    no-op on already-current vault.
  - `TestMixedFormatVault` — mixed-format vaults readable; upgrade
    migrates only legacy entries.
  - `TestNoPlaintextSpill` — distinctive plaintext marker never appears
    in any vault file after upgrade.
  - `TestDefenses` — rejects unsupported `target_format_version`; rejects
    meta-vs-blob format mismatch with `SignatureError`.
  - `TestFormatVersionConstants` — sanity checks on the constants block.

**Verification:**
- 438 tests pass (was 418 in v0.1: +20 migration tests, +1 elsewhere).
- 1 pre-existing sslyze-conditional skip (unchanged).
- `mypy --strict qwashed/` clean (unchanged surface).
- v0.1 vaults written before this change still verify and read under
  v0.2 readers (backward-compat preserved by the omit-when-1 rule on
  the canonical-JSON body).

---

### 3.7 — GPG-encrypted disclosure channel  **S**

**Why:** `docs/SECURITY.md:26` defers GPG-encrypted email vulnerability
disclosure to v0.2 because no project GPG identity exists.

**Scope:**

- Generate a project GPG key (Ed25519, no passphrase on the offline
  copy; passphrase-protected on the maintainer's working copy). Publish
  the public key in `release_keys/qwashed-disclosure.pgp` and the
  fingerprint in `docs/SECURITY.md`.
- Update `docs/SECURITY.md` §"Preferred disclosure channels" to list
  GPG as channel 2, age as channel 1 (parity).
- Cross-publish the GPG fingerprint in the same three independent
  channels as the release-signing key fingerprint.

**Files touched:**
`release_keys/qwashed-disclosure.pgp`, `docs/SECURITY.md`,
`docs/VERIFY_RELEASE.md` (cross-reference).

**Dependencies:** GPG key generation happens **once**, offline, by the
maintainer. Not a CI step.

**Risk:** key compromise of the disclosure key would allow an attacker
to impersonate the maintainer and intercept reports. Mitigation: keep
the private key on hardware-backed storage (YubiKey or equivalent),
publish a revocation certificate at generation time, document the
revocation procedure in `RELEASE_HANDOFF.md`.

**Done means:**
- `gpg --verify` against the published key works for an encrypted
  disclosure email round-trip.
- SECURITY.md no longer says "deferred to v0.2."

---

### 3.8 — Performance benchmarks  **S**

**Why:** README §229 promises v0.2 will close the "performance
benchmarks" gap. Civil-society IT teams need to know whether running
`qwashed audit` on a 1000-target list will finish in seconds or hours.

**Scope:**

- `benchmarks/` directory at repo root with three reproducible scripts:
  - `bench_audit.py`: scan synthetic 100 / 1000 / 10000-target list
    against the `StaticProbe` (no network), measure wall-clock,
    per-finding scoring time, total report bytes.
  - `bench_vault.py`: vault put / get / list / verify on 100 / 1000 /
    10000 entries of 1 KiB / 1 MiB / 64 MiB each.
  - `bench_kem.py`: hybrid encap/decap throughput, hybrid sign/verify
    throughput. Numbers reproducible across machines via per-CPU
    normalization.
- `benchmarks/results/` with one JSON file per `(version, machine)`
  pair, signed with the release key.
- Document the methodology in `docs/BENCHMARKS.md`.

**Files touched:**
`benchmarks/`, `docs/BENCHMARKS.md`, `README.md` (link to
`docs/BENCHMARKS.md`).

**Dependencies:** none.

**Risk:** numbers go stale. Mitigation: re-run benchmarks as part of
each release's quality gate; record the date and machine in the JSON.

**Done means:**
- Three benchmark scripts run cleanly on macOS arm64 and Linux x86_64.
- v0.2.0 ships with one signed JSON results file per benchmark.
- README links to a section that lets a user predict their wall-clock.

---

### 3.9 — Mesh / disaster-network deployment profile  **S**

**Why:** BUILD_PLAN §16 lists this. The work item is small because
"profile" here means a YAML threat profile + a docs section, not a new
networking subsystem.

**Scope:**

- `qwashed/audit/profiles/mesh_disaster.yaml`: weights tuned for
  scenarios where audit findings cannot be sent over the public
  internet, where the operator is using mesh / store-and-forward
  networks, and where archival adversary likelihood is reduced (no
  cloud archival possible) but on-link sniffing likelihood is elevated.
- `docs/THREAT_PROFILES.md`: add a section explaining when to use this
  profile (Briar, Meshtastic, disaster-relief deployments, post-disaster
  comms).
- A worked scenario in `docs/AUDIT_GUIDE.md`.

**Files touched:**
`qwashed/audit/profiles/mesh_disaster.yaml`,
`qwashed/audit/profile_loader.py` (register the new profile),
`docs/THREAT_PROFILES.md`, `docs/AUDIT_GUIDE.md`,
`tests/audit/test_profile_loader.py`.

**Dependencies:** none.

**Risk:** mistuned weights produce misleading severity. Mitigation:
golden test the profile against fixtures that exercise the edge cases
the weights were designed for.

**Done means:**
- `qwashed audit profiles` lists `mesh_disaster`.
- Profile passes the existing monotonic-thresholds + domain-monotonic
  validation invariants.

---

## 4. Sequencing

Two work items depend on others; the rest are independent and can land
in any order.

```
3.4 NativeTlsProbe ──────┐
3.2 PGP/S/MIME probe ────┼── 3.5 richer scoring (uses extended findings)
3.3 WG/IPsec probe ──────┘
3.6 vault format v0.2 (independent — vault module)
3.1 hybrid release signing (independent — needed for the actual v0.2 release)
3.7 GPG disclosure key (independent — out-of-band)
3.8 benchmarks (after 3.4 / 3.6 so numbers reflect v0.2 code)
3.9 mesh profile (independent)
```

Recommended landing order:
1. ~~**3.6 vault format v0.2**~~ — **LANDED 2026-05-05.** Exercises the
   migration machinery on a sleepy week with low risk.
2. ~~**3.4 NativeTlsProbe**~~ — **LANDED 2026-05-06.** Removes the
   sslyze maintenance overhang; hand-rolled TLS 1.2/1.3 probe on
   `cryptography` only is now the default.
3. ~~**3.2 PGP/S-MIME**~~ — **LANDED 2026-05-06.** Hand-rolled OpenPGP
   parser + `cryptography.x509` for S/MIME, `MultiplexProbe` routing,
   file-only `AuditTarget` with relative-path resolution. **3.3 WG/IPsec**
   still pending.
4. ~~**3.5 scoring**~~ — **LANDED 2026-05-06.** Bounded v0.2 boost
   catalog (RSA/ECC key length, cert lifetime horizon, non-AEAD
   cipher), per-arm cap `+0.10`, total cap `+0.20`, threat-profile
   overrides, `--explain` flag.
5. **3.9 mesh profile**, **3.7 GPG key**, **3.8 benchmarks** at any
   point.
6. **3.1 hybrid release signing** is the last item — once landed, it
   becomes the mechanism that publishes v0.2.0.

---

## 5. Acceptance criteria for the v0.2.0 release

A v0.2.0 build is releasable when **all** of the following are true:

- [ ] All nine work items in §3 are landed and tested.
- [ ] `pytest` passes ≥ 500 tests (current 418 + new probe / scoring /
      vault-migration / benchmark tests). No new skips except the
      pre-existing optional-extras conditional.
- [ ] `mypy --strict qwashed/` clean.
- [ ] `ruff check .` and `ruff format --check .` clean.
- [ ] FIPS 203 / 204 KAT vectors still pass (algorithm choices unchanged).
- [ ] `qwashed verify` round-trips both v0.1 and v0.2 release artifacts
      under hybrid release signing.
- [ ] `qwashed vault upgrade` round-trips a v0.1 vault → v0.2 vault with
      bytes-identical retrieval and a complete signed audit-log trail.
- [ ] Benchmarks are re-run, signed, and committed under
      `benchmarks/results/`.
- [ ] `CHANGELOG.md` `[0.2.0]` section is filled in with the same
      structure as `[0.1.0]` (Added / Changed / Verified blocks per
      work item).
- [ ] `THREAT_MODEL.md` version header bumped to v0.2.0; no out-of-date
      v0.1-specific claims.
- [ ] `docs/SECURITY.md` GPG-disclosure-deferred line removed; v2
      release-signing-key fingerprint published.
- [ ] `RELEASE_HANDOFF.md` updated with the hybrid release-signing
      procedure.
- [ ] This `docs/ROADMAP.md` updated to reflect what shipped vs what
      slipped to v0.3.

---

## 6. Reconciliation with existing docs

This roadmap resolves the following inconsistencies that existed at
the time of writing. All other docs should be updated to point at this
roadmap as the source of truth.

| Doc                        | Conflicting claim                                                  | Resolution in this roadmap                                                                                  |
|----------------------------|--------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| `README.md` §229–233       | "v0.2 roadmap closes ... threshold export"                          | **Wrong.** Threshold / multi-recipient unsealing is in v0.3 (`group vault`). README to be edited to remove. |
| `README.md` §229–233       | "v0.2 roadmap closes ... hybrid release signing"                    | **Confirmed** — see §3.1.                                                                                   |
| `README.md` §229–233       | "v0.2 roadmap closes ... performance benchmarks"                    | **Confirmed** — see §3.8.                                                                                   |
| `README.md` §229–233       | "v0.2 roadmap closes ... broader probe coverage"                    | **Confirmed** — see §3.2, §3.3, §3.4.                                                                       |
| `QWASHED_BUILD_PLAN.txt` §16 v0.2 | Lists hand-rolled TLS, email PGP/S-MIME, WG/IPsec, mesh profile | **Confirmed**, plus this roadmap adds: hybrid release signing (§3.1), richer scoring (§3.5), vault format v0.2 (§3.6), GPG disclosure (§3.7), benchmarks (§3.8). |
| `QWASHED_BUILD_PLAN.txt` §16 v0.3 | Group vault / multi-recipient                                  | **Confirmed v0.3** — explicitly NOT v0.2. README to be aligned.                                             |
| `docs/SECURITY.md:26`      | GPG-encrypted email "deferred to v0.2"                              | **Confirmed** — see §3.7.                                                                                   |
| `docs/SECURITY.md:104`     | Hybrid release signing "on the v0.2 roadmap"                        | **Confirmed** — see §3.1.                                                                                   |
| `qwashed/audit/scoring.py:22` | Higher-order scoring "deferred to v0.2"                          | **Confirmed** — see §3.5.                                                                                   |
| `THREAT_MODEL.md` §"Versioning and forward compatibility" | v0.2 introduces new HKDF info string + `qwashed vault upgrade` | **Confirmed** — see §3.6. v0.2 keeps the algorithm but exercises the migration path. |
| `RELEASE_HANDOFF.md:259`   | "hold the PyPI publish for a v0.1.1 or v0.2"                        | **Recommend:** publish to PyPI at v0.2.0 launch, after hybrid release signing lands. (Not a v0.2 work item; an operational decision.) |

After this roadmap is approved, the README v0.2 paragraph should be
edited to:

> "The v0.2 roadmap (`docs/ROADMAP.md`) closes the developer-facing
> gaps above: broader probe coverage (PGP, S/MIME, WireGuard, IPsec),
> hybrid Ed25519 || ML-DSA-65 release signing, richer HNDL scoring,
> a vault-format migration path, signed performance benchmarks, and
> a GPG-encrypted disclosure channel. Threshold / multi-recipient
> decryption is on the v0.3 roadmap."

---

## 7. v0.3 outlook (informational, not committed)

Items currently scoped to v0.3 per BUILD_PLAN §16 + this roadmap's
deferrals:

- Minimal GUI (Tauri or PySide).
- Group vault / multi-recipient unsealing (the "threshold export"
  feature the README mistakenly attributed to v0.2).
- Hardware-token (YubiKey, OnlyKey) support for vault identity.
- Localization (i18n).
- Optional: PGP keyring / WKD / HKP discovery if the v0.2 PGP probe is
  scope-limited to local key files.

## 8. v1.0 outlook (informational, not committed)

- Stable algorithm tables, frozen artifact schema.
- Formal threat-model review.
- Third-party security audit.
- Reproducible builds documented end-to-end.
- Trademark registration on "Qwashed".
- Long-term-support policy defined.

---

## 9. How this document evolves

- One PR per work item in §3. Each PR includes the work item's
  "Done means" checklist in the PR description and ticks it before
  merge.
- When a work item lands, mark it `[x]` here and add a brief link to
  the merged PR.
- When v0.2.0 ships, fold §3 into `CHANGELOG.md` `[0.2.0]` and
  rewrite §3 as the v0.3 work-item list.
- When the scope changes (item dropped, item added, item moved between
  releases), update this file in the same PR — never silently.
