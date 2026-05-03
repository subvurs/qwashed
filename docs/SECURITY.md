# Security Policy

## Reporting a vulnerability

Qwashed is intended for use by people whose communications are targeted by
state-scale adversaries. Vulnerability disclosure must reflect that.

**Do not open public GitHub issues for cryptographic vulnerabilities, key
disclosure bugs, signature forgery vectors, or anything that could be exploited
to read or forge protected data.**

### Preferred disclosure channels (in order)

1. **age-encrypted email** to the project's published age recipient:

   ```
   age18xezt9y3hwns0akylm6tg3e3aztc8qeylh2cwe5np9suq6ql5f5s0e6slv
   ```

   Encrypt your report with `age -r <recipient> -o report.age report.txt`
   and email the resulting `report.age` to the maintainer (contact address
   in the project README / repository metadata). The corresponding age
   private key is held offline by the maintainer and is not stored on any
   network-connected machine.

2. **GPG-encrypted email** — *deferred to v0.2.* No project GPG identity
   is published for v0.1; reporters who require GPG should contact the
   maintainer through channel 1 or 3 to negotiate an alternate channel.

3. If neither encrypted channel is available, a private security advisory
   via GitHub's "Report a vulnerability" feature on the repository.

We do **not** accept disclosure via Twitter/X DMs, Slack, Discord, Telegram,
or any other plaintext-by-default channel. We do not run a bug-bounty program
in v0.1; rewards may be considered post-v1.0.

### What to include

- A description of the vulnerability and its impact.
- Steps to reproduce, ideally with a minimal proof-of-concept.
- Affected versions of Qwashed and any dependencies in scope.
- Your preferred attribution name (or "anonymous").
- Whether you would like the disclosure timeline accelerated or extended for
  any reason (we will negotiate in good faith).

### What to expect

- Acknowledgment within 7 calendar days.
- A triage decision (accepted / out-of-scope / duplicate) within 21 calendar
  days.
- For accepted reports:
  - A coordinated disclosure timeline (default: 90 days from triage decision,
    extendable on request).
  - A pre-release patch shared with the reporter for verification.
  - Public credit in the changelog and the release announcement (unless you
    request anonymity).

## Scope

### In scope

- Confidentiality, integrity, or authenticity violations in `qwashed.vault`.
- Signature forgery against `qwashed audit` artifacts.
- Misclassification in `qwashed audit` that systematically understates
  HNDL exposure (e.g., a classical-only cipher being labeled hybrid-PQ).
- Tamper-detection bypasses in the vault audit log.
- Side-channel leakage from Qwashed code (not from upstream liboqs / cryptography,
  which have their own disclosure processes).
- Any vulnerability that allows a network attacker to deanonymize Qwashed users
  or correlate audit results with identities.
- Build / supply-chain issues in Qwashed's release artifacts.

### Out of scope (in v0.1)

- Endpoint compromise scenarios (see THREAT_MODEL.md §N1).
- Side-channel issues in liboqs, `cryptography`, or other upstream
  dependencies — please report to those projects directly.
- Coercion / rubber-hose attacks (THREAT_MODEL.md §N2).
- Issues in v0.1 that are explicitly documented as known limitations
  in `THREAT_MODEL.md` or `CHANGELOG.md`.
- Denial-of-service attacks against the local CLI (e.g., a malformed audit
  config that causes a crash).

## Cryptographic dependencies

Qwashed's security relies on the correctness of its dependencies:

- [`cryptography`](https://pypi.org/project/cryptography/) — for X25519, Ed25519,
  AES-256-GCM, HKDF.
- [`liboqs-python`](https://pypi.org/project/liboqs-python/) wrapping
  [liboqs](https://github.com/open-quantum-safe/liboqs) — for ML-KEM-768
  and ML-DSA-65.
- [`argon2-cffi`](https://pypi.org/project/argon2-cffi/) — for vault passphrase
  derivation.

We pin tested version ranges in `pyproject.toml` and ship NIST FIPS 203 / 204
known-answer-test vectors so any silent change to upstream output is caught at
test time. Vulnerabilities in these libraries should be reported upstream first;
we'll respond by pinning around the issue or releasing an advisory.

## Verification of releases

Each Qwashed release is signed with a project Ed25519 key (hybrid
Ed25519 + ML-DSA-65 release signing is on the v0.2 roadmap).

### v0.1.0 release-signing key

| Field            | Value                                                 |
|------------------|-------------------------------------------------------|
| Algorithm        | Ed25519                                               |
| Identifier       | `qwashed-release-key-v1`                              |
| Fingerprint      | `63ca4ae93b906a13` (first 16 hex of SHA-256 of the raw 32-byte public key) |
| Public key file  | [`release_keys/qwashed-release.pub`](../release_keys/qwashed-release.pub) |

Pin this fingerprint at first use. It is published in three independent
channels so an attacker would have to compromise all three simultaneously
to forge a release:

1. This file (`docs/SECURITY.md`).
2. `release_keys/qwashed-release.pub` in the repository.
3. The project's web presence (TBD before publication; until then,
   confirm the fingerprint via the GitHub release page or by re-cloning
   the repository over HTTPS).

Source tarballs and wheels ship with detached SHA-256 sums and Ed25519
signatures, plus a project-wide `SHA256SUMS` + `SHA256SUMS.sig`
manifest. Step-by-step verification instructions are in
[`docs/VERIFY_RELEASE.md`](VERIFY_RELEASE.md).

Key rotation events are announced in `CHANGELOG.md` and are signed by
the previous release key.

## Supported versions

Qwashed is in pre-release. Until v0.1.0, all development versions are
**unsupported** and **must not** be used in production or for the protection of
real sensitive data.

Once v0.1.0 ships, the support policy will be:

| Version line | Status                                          |
|--------------|-------------------------------------------------|
| `0.1.x`      | Active development; security fixes for 18 months from `0.1.0` release. |
| `0.x.y`      | Subsequent minor releases supersede prior minors. Two minor versions supported in parallel. |
| `1.0.0+`     | Long-term-support policy to be defined ahead of `1.0.0`. |
