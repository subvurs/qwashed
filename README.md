# Qwashed

**Quash quantum threats. Keep your data clean.**

Free post-quantum hygiene for civil society:

- **`qwashed audit`** — scans your communication surface for cryptography that
  will be broken by future quantum computers, scores your Harvest-Now-Decrypt-Later
  exposure under a civil-society threat profile, and produces a signed migration
  roadmap.
- **`qwashed vault`** — local-only, hybrid-encrypted, hybrid-signed vault for
  sensitive documents, source notes, and evidence. Combines NIST-standardized
  post-quantum cryptography (ML-KEM-768, ML-DSA-65) with classical algorithms
  (X25519, Ed25519) so an attacker has to break both.

> **Status: v0.1.0 (alpha).** First public release. The cryptographic core,
> HNDL auditor, and hybrid PQ vault are all functional and tested. Treat
> v0.1.x as evaluation-grade software: suitable for pilot deployments by
> civil-society IT teams, not yet a substitute for an audited mature
> system. See [QWASHED_BUILD_PLAN.txt](./QWASHED_BUILD_PLAN.txt) for the
> full build plan and acceptance criteria, and
> [`THREAT_MODEL.md`](./THREAT_MODEL.md) for in-scope / out-of-scope
> adversaries.

---

## Why Qwashed exists

State-scale archival adversaries are recording encrypted internet traffic
**right now** — banking on future quantum computers to decrypt it in 5–15 years.
The communications most archived today belong to journalists, organizers, asylum
seekers, abortion-access networks, immigrant-rights organizations, queer
communities in hostile jurisdictions, union organizers, public-defender clients,
community health centers, legal-aid clinics, and indigenous-rights advocates.

Default enterprise post-quantum migration trajectories invert the equity-correct
order: well-resourced firms migrate first, civil society last. Qwashed exists to
flip that order. Free, offline-capable, no telemetry, no accounts, no paid tier.

See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for what Qwashed defends against and,
just as importantly, what it does **not** defend against.

---

## Install

```bash
# Core only (smallest install, library APIs)
pip install qwashed

# Audit module
pip install "qwashed[audit]"

# Vault module
pip install "qwashed[vault]"

# Everything user-facing
pip install "qwashed[full]"
```

The vault module depends on
[`liboqs-python`](https://pypi.org/project/liboqs-python/), which wraps the
upstream [liboqs](https://github.com/open-quantum-safe/liboqs) C library.
Wheels are published for macOS arm64 and Linux x86_64. On other platforms you
may need to install liboqs first (`brew install liboqs` on macOS, package manager
or build from source elsewhere).

Verify a downloaded release before installing from a third-party mirror —
see [`docs/VERIFY_RELEASE.md`](./docs/VERIFY_RELEASE.md).

---

## Quickstart

The five-minute install + first audit + first vault flow lives in
[`docs/QUICKSTART.md`](./docs/QUICKSTART.md). Preview:

```bash
# Audit a list of endpoints under the journalism threat profile
qwashed audit run my-audit.yaml --profile journalism -o audit.json

# Verify a previously signed audit artifact
qwashed verify audit.json

# Initialize a new vault
qwashed vault init

# Store a sensitive file
qwashed vault put source-interview-notes.md --name "session-1"

# Verify the vault hasn't been tampered with
qwashed vault verify
```

Full guides:

- [`docs/QUICKSTART.md`](./docs/QUICKSTART.md) — five-minute first run.
- [`docs/AUDIT_GUIDE.md`](./docs/AUDIT_GUIDE.md) — civil-society IT teams.
- [`docs/VAULT_GUIDE.md`](./docs/VAULT_GUIDE.md) — vault scenarios + runbooks.
- [`docs/THREAT_PROFILES.md`](./docs/THREAT_PROFILES.md) — write your own
  scoring profile.
- [`docs/VERIFY_RELEASE.md`](./docs/VERIFY_RELEASE.md) — verify downloads.

---

## Design principles

- **Free forever.** Apache 2.0. No paid tier. No telemetry. No accounts. No
  phone-home. Verified by network-disabled test runs in CI.
- **Threat-profile-first.** Journalist, organizer, clinic, public-defender, and
  immigrant-rights profiles are first-class, not afterthoughts. Enterprise is
  provided for comparison and deprioritized.
- **Auditable and reproducible.** Every report is signed (Ed25519, optionally
  hybrid Ed25519 + ML-DSA-65), every input is canonicalized
  ([RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785)), every score is
  recomputable from raw probe data. `--deterministic` mode produces bit-identical
  output across runs for legal evidence preservation.
- **Hybrid by default.** Suspenders and belt: classical (X25519, Ed25519) plus
  NIST-standardized post-quantum (ML-KEM-768 / FIPS 203, ML-DSA-65 / FIPS 204).
  An attacker has to break both. If ML-KEM falls to cryptanalysis tomorrow,
  X25519 still protects you. If a quantum computer arrives in 2030, ML-KEM
  still protects you.
- **Offline-capable.** Civil-society users cannot assume reliable cloud access,
  nor should they have to.
- **Honest scope.** Qwashed does not undo prior archive exposure. It stops
  further bleeding and provides verifiable migration proof.

---

## What Qwashed is not

- **Not a Signal replacement.** Use Signal (or another PQXDH-deploying messenger)
  for messaging.
- **Not a TLS scanner that competes with sslyze / testssl.sh / SSL Labs.**
  It uses similar primitives but produces a different artifact: a threat-profiled,
  signed, civil-society-oriented HNDL audit, not a generic security report.
- **Not a quantum-hardware tool.** Runs on a laptop. Runs offline. No backends.
- **Not a substitute for operational security training, legal counsel, or threat
  modeling by a qualified practitioner.** Qwashed is one layer in
  defense-in-depth, not a guarantee.

---

## Relationship to QCert

Qwashed has a conceptual sibling, [QCert](../../commercialization/path_d_qcert/),
which is a separately licensed commercial product for QKD (quantum key
distribution) certification — a different layer of the post-quantum stack.

The two share an epistemic posture (fail-closed, RFC 8785 canonical artifacts,
signed reproducibility) but **no code**. Qwashed reimplements the small generic
infrastructure pieces it needs. The two products can evolve independently
without licensing entanglement.

---

## Contributing

Contributions welcome under the terms in
[`docs/CONTRIBUTING.md`](./docs/CONTRIBUTING.md). Security issues:
see [`docs/SECURITY.md`](./docs/SECURITY.md) — please do **not**
open public GitHub issues for cryptographic vulnerabilities.

---

## License

Apache License 2.0. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

The name "Qwashed" is a trademark. See `NOTICE` for the trademark statement and
its narrow restriction on derivative works that meaningfully alter the security
posture or add telemetry.
