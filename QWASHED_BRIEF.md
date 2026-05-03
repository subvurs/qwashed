# Qwashed — 2-page brief

**Version:** v0.1.0 (alpha) · **License:** Apache-2.0 · **Author:** Mark Eatherly · **Date:** 2026-05-01

---

## What Qwashed is

Qwashed is a **free, Apache-2.0 post-quantum cryptographic hygiene platform for civil society** — journalism, healthcare, legal aid, human-rights organisations, small NGOs. It exists because the harvest-now-decrypt-later (HNDL) threat is already here: TLS handshakes captured today against classical-only ECDH/RSA can be retroactively broken once a CRQC (cryptographically-relevant quantum computer) becomes available. Civil society is the population least equipped to migrate, and the most exposed when archived data is decrypted.

The project deliberately stays out of the Quasmology / Nyx research line. There is no Chaos Valley, no Baiame boost, no NBEE terminology. Qwashed is pure standards-track post-quantum cryptography (NIST FIPS 203 / 204) wrapped around vetted classical primitives (`cryptography`, `argon2-cffi`, `liboqs-python`).

## What Qwashed does

Qwashed ships **two tools** built on a small shared core, plus signed audit/release tooling.

1. **`qwashed audit` — HNDL Auditor.** Probes a list of TLS / SSH endpoints, classifies their cryptographic posture (classical-only / hybrid-PQ / pure-PQ / unknown), scores HNDL exposure under a configurable civil-society threat profile, and produces a signed migration roadmap. Supports four bundled threat profiles (default, journalism, healthcare, legal) and arbitrary custom YAML profiles. Output is canonical-JSON + HTML/PDF report, Ed25519-signed, optionally bit-identical (`--deterministic` mode).

2. **`qwashed vault` — Hybrid post-quantum vault.** Local-only encrypted file/message store. Uses **X25519 || ML-KEM-768** for key encapsulation and **Ed25519 || ML-DSA-65** for signatures (defence-in-depth: an attacker must break both legs to compromise content). Argon2id-derived KEK protects vault metadata; tamper-evident hash-chained audit log records every operation.

3. **Signed-release pipeline.** Per-artifact `.sha256` + Ed25519 `.sig`, project-wide `SHA256SUMS` + `SHA256SUMS.sig`, public release-key fingerprint published in three independent channels (release-key file, `SECURITY.md`, project announcement). Documented end-to-end verification flow lets a third party install qwashed without trusting the package index.

**Test status:** 417 tests pass + 1 sslyze-conditional skip (Python 3.13 / macOS arm64). `mypy --strict` clean over 27 source files. Built and signed dist artefacts: `qwashed-0.1.0.tar.gz`, `qwashed-0.1.0-py3-none-any.whl` (release-key fingerprint `63ca4ae93b906a13`).

## Architecture in one diagram

```
        ┌──────────────────────────┐
        │  qwashed/core            │  canonical.py · errors.py · kdf.py
        │  (shared primitives)     │  report.py · schemas.py · signing.py
        └──────────┬───────────────┘
                   │
        ┌──────────┴───────────────┐
        │                          │
┌───────▼────────┐         ┌───────▼────────────────┐
│ qwashed/audit  │         │ qwashed/vault          │
│  (HNDL probe + │         │  (hybrid-PQ KEM + sig  │
│   classify +   │         │   + hash-chained audit │
│   score + sign │         │   log + local store)   │
│   roadmap)     │         └────────────────────────┘
└────────────────┘
```

A single CLI (`qwashed/cli.py`) dispatches into `qwashed audit ...`, `qwashed vault ...`, and `qwashed verify <artefact>` (artefact-internal signature verification, distinct from release verification).

---

## Relevant filenames

### Top-level

| Path | Role |
|------|------|
| `README.md` | Project landing page, install, quickstart pointer |
| `CHANGELOG.md` | Versioned change log; v0.1.0 entry dated 2026-04-30 |
| `THREAT_MODEL.md` | Adversary model, defended/not-defended scope |
| `LICENSE`, `NOTICE` | Apache-2.0 + attribution |
| `pyproject.toml` | Hatchling build, ruff/mypy config, optional extras (`audit`, `vault`, `dev`, `all`) |
| `QWASHED_BUILD_PLAN.txt` | Internal phase-by-phase build plan (Phases 0–4 complete) |
| `RELEASE_HANDOFF.md` | Manual release steps still required (key publication, tag, PyPI, GH release) |
| `release_keys/qwashed-release.pub` | Public Ed25519 release-signing key (fingerprint `63ca4ae93b906a13`) |

### `qwashed/core/` — shared primitives

| File | What it does |
|------|--------------|
| `canonical.py` | RFC 8785 canonical JSON for signed artefacts |
| `errors.py` | Typed exception hierarchy with stable `error_code`s |
| `kdf.py` | HKDF-SHA256 + Argon2id wrappers, fail-closed parameter floors |
| `signing.py` | Ed25519 `SigningKey` / `VerifyKey` (raw 32-byte / base64) |
| `schemas.py` | Pydantic-v2 base models reused across audit + vault |
| `report.py` | HTML/PDF rendering helpers (jinja2 + reportlab) |

### `qwashed/audit/` — HNDL auditor

| File | What it does |
|------|--------------|
| `cli.py` | `qwashed audit` subcommand parser |
| `pipeline.py` | Orchestrates probe → classify → score → roadmap → sign |
| `probe.py` | `Probe` ABC + `StdlibTlsProbe`, `SslyzeTlsProbe`, `StaticProbe` |
| `classifier.py` | Maps cipher / KEX / sig algorithm to posture category |
| `scoring.py` | `score = category_weight × archival_likelihood`; aggregation `max`/`mean` |
| `roadmap.py` | Generates per-target migration steps + severity ranking |
| `report_html.py` | Renders the audit HTML report from canonical JSON |
| `schemas.py` | `AuditTarget`, `ProbeResult`, `ThreatProfile`, `AuditReport` models |
| `profile_loader.py` | Loads bundled + user profile YAML, fail-closed validation |
| `profiles/{default,journalism,healthcare,legal}.yaml` | Four bundled threat profiles |

### `qwashed/vault/` — hybrid-PQ vault

| File | What it does |
|------|--------------|
| `cli.py` | `qwashed vault` subcommand parser |
| `hybrid_kem.py` | X25519 ‖ ML-KEM-768 encapsulation (FIPS 203) |
| `hybrid_sig.py` | Ed25519 ‖ ML-DSA-65 signing (FIPS 204) |
| `store.py` | On-disk layout, AEAD-wrapped item store |
| `audit_log.py` | Hash-chained tamper-evident log of vault operations |

### Top-level CLI / entry

| File | Role |
|------|------|
| `qwashed/__init__.py` | Public package metadata, `__version__ = "0.1.0"` |
| `qwashed/__main__.py` | `python -m qwashed` entry |
| `qwashed/cli.py` | Top-level dispatcher (`audit` / `vault` / `verify`) |

### `docs/` — user-facing documentation

| File | Role |
|------|------|
| `QUICKSTART.md` | 5-minute first-run flow |
| `AUDIT_GUIDE.md` | Full HNDL-audit walkthrough |
| `VAULT_GUIDE.md` | Vault setup, unseal, signing |
| `THREAT_PROFILES.md` | Profile schema, weights, scoring formula, custom-profile authoring |
| `VERIFY_RELEASE.md` | Third-party release-verification flow (key → SHA256SUMS → install) |
| `SECURITY.md` | Disclosure policy, age/GPG recipients (TBD before publish), key fingerprints |
| `CONTRIBUTING.md` | Style, CLA pointer, PR workflow |

### `examples/audit/`

`civic_websites.yaml`, `journalism_endpoints.yaml`, `healthcare_endpoints.yaml`, `legal_endpoints.yaml` — ready-to-run target lists.

### `tests/` — 418 tests (1 sslyze-conditional skip)

`tests/core/test_{canonical,errors,kdf,report,schemas,signing}.py` (core primitives) · `tests/audit/test_{classifier,cli,golden,pipeline,probe,profile_loader,report_html,roadmap,schemas,scoring}.py` (auditor) · `tests/vault/test_{audit_log,cli,hybrid_kem,hybrid_sig,store}.py` (vault) · `tests/test_smoke.py`, `tests/test_verify_cli.py` (top-level).

---

*One-page summary: Qwashed is HNDL audit + hybrid-PQ vault for civil society, Apache-2.0, v0.1.0 alpha, 417/418 tests green, signed dist artefacts ready, awaiting human-action release steps documented in `RELEASE_HANDOFF.md`.*
