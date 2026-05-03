# Qwashed Threat Model

> **Version:** v0.1.0
> **Last reviewed:** 2026-04-30
> **Audience:** Civil-society IT teams, security researchers, journalists,
> legal-aid technologists, public-interest cryptographers.

This document describes what Qwashed defends against, what it does **not**
defend against, and how its hybrid post-quantum design addresses each adversary.
If your situation is not covered here, treat Qwashed as one layer in
defense-in-depth, not a guarantee.

---

## TL;DR

Qwashed defends against four named adversaries (T1–T4) and explicitly does **not**
defend against five categories of attack (N1–N5). Read both lists before
deploying.

| ID | Adversary                                                                     | Defense               |
|----|-------------------------------------------------------------------------------|-----------------------|
| T1 | State-scale archival adversary with future quantum capability                 | Hybrid PQ + audit     |
| T2 | Cloud-provider compulsion (subpoena, seizure)                                 | Local vault           |
| T3 | Supply-chain compromise of a single PQ library                                | Hybrid construction   |
| T4 | Cryptanalytic break of one hybrid component (classical OR PQ)                 | Hybrid construction   |
|    |                                                                               |                       |
| N1 | Endpoint compromise (malware, RAT, keylogger on the user's machine)           | Out of scope          |
| N2 | Coercion of the user (rubber-hose, legal compulsion to decrypt)               | Out of scope          |
| N3 | Side-channel attacks against PQ implementations                               | Library-dependent     |
| N4 | Traffic-analysis / metadata-correlation attacks                               | Out of scope          |
| N5 | Targeted persistent on-target adversary (TAO-class)                           | Out of scope          |

---

## In-scope adversaries

### T1. State-scale archival adversary with future quantum capability

**Capability:** Bulk-records encrypted internet traffic today. Operates
fiber-tap programs, ISP-level interception, or compelled provider cooperation.
Stores ciphertext indefinitely, betting on a cryptographically-relevant quantum
computer (CRQC) arriving in the 2030s or 2040s. RSA-2048, RSA-3072, ECDH P-256,
ECDH P-384, ECDSA P-256, and ECDSA P-384 are all known to be polynomial-time
broken by Shor's algorithm on a sufficiently large, fault-tolerant CRQC.

**Goal:** Decrypt archived communications retroactively. Recover the identities
of journalists' sources, organizers' contacts, asylum applicants' family
networks, abortion-access caregivers, queer-community members in hostile
jurisdictions, union sympathizers, and clinic patients.

**Qwashed's defense:**
- `qwashed audit` identifies which of an organization's TLS / SSH endpoints are
  still negotiating classical-only key exchange. Each endpoint is scored under
  a civil-society threat profile so the migration roadmap targets the highest-
  exposure surfaces first.
- `qwashed vault` encrypts at-rest data with **hybrid** ML-KEM-768 (FIPS 203)
  combined with X25519. Even a future CRQC that breaks ML-KEM cannot recover
  vault contents without also breaking X25519 — and vice versa.

**Limitations:**
- Qwashed cannot retroactively protect data already archived by the adversary.
  That ciphertext is gone; the goal is to stop further bleeding.
- Qwashed cannot force communication partners to negotiate hybrid PQ. Both
  endpoints must support it.

### T2. Cloud-provider compulsion adversary

**Capability:** Issues subpoenas, gag orders, national-security letters, or
legal demands to cloud providers, hosting companies, email services, or backup
providers. Compels disclosure of customer data, encryption keys, or both.
Includes hostile-jurisdiction governments seizing physical infrastructure.

**Goal:** Read encrypted-at-rest data without the data subject's knowledge or
consent.

**Qwashed's defense:**
- `qwashed vault` is **local-only** by design. There is no Qwashed cloud, no
  Qwashed account, no Qwashed backup service. A cloud provider cannot disclose
  what it does not hold.
- The vault's hybrid signature scheme (Ed25519 + ML-DSA-65) and hash-chained
  audit log make tampering tamper-evident. A provider that holds a backup
  copy of an exported vault cannot silently modify entries without breaking
  signatures.

**Limitations:**
- If the user voluntarily syncs the vault directory to a cloud service, the
  encrypted blobs are still subject to the provider's compulsion. The hybrid
  encryption protects confidentiality even in that case, but availability and
  metadata (file names, sizes, timestamps) leak.
- Qwashed cannot defend against compulsion of the user themselves — see N2.

### T3. Supply-chain compromise of a single PQ library

**Capability:** Compromises the build pipeline of a PQ cryptography library
(liboqs, a Python wrapper, or a downstream dependency). Inserts a backdoor,
weakens parameter selection, or exfiltrates keys.

**Goal:** Silently break the post-quantum portion of an organization's
cryptography.

**Qwashed's defense:**
- The **hybrid construction** is the defense. Qwashed never trusts a single
  PQ library to provide all of its security. Every encryption operation
  combines a classical primitive (X25519, Ed25519) with a PQ primitive
  (ML-KEM-768, ML-DSA-65). A backdoor in liboqs that compromises ML-KEM
  does not compromise X25519, and the AEAD key is derived from the
  concatenation of both shared secrets via HKDF-SHA256.
- Qwashed pins liboqs-python to a tested version range and ships KAT
  (known-answer-test) vectors from FIPS 203 / 204 in the test suite. Any
  silent change to library output breaks tests at install time.

**Limitations:**
- A simultaneous compromise of *both* the classical and the PQ library would
  defeat the hybrid construction. Mitigation: the classical primitives are in
  the well-audited `cryptography` package (RustCrypto + OpenSSL), which has
  a much larger attack surface for the supply-chain adversary to compromise
  undetected than liboqs.

### T4. Cryptanalytic break of one hybrid component

**Capability:** Discovers a mathematical break in either ML-KEM-768 or
ML-DSA-65 (post-deployment). Several lattice-based schemes have already been
broken during NIST's standardization process; structurally, the post-quantum
algorithms are younger and less battle-tested than the classical ones.

**Goal:** Decrypt or forge messages protected by Qwashed's PQ component.

**Qwashed's defense:**
- Same as T3 — the hybrid construction. Breaking ML-KEM does not yield the
  vault's AEAD key without also breaking X25519. Breaking ML-DSA does not
  let an adversary forge a hybrid signature without also forging Ed25519.
- The classical primitives (X25519, Ed25519) have been deployed at internet
  scale for over a decade with no break.
- If a break does occur, Qwashed's module-versioned HKDF info string
  (`qwashed/vault/v0.1/kem`) means a v0.2 release can introduce a new
  algorithm without breaking the v0.1 vault format.

**Limitations:**
- A simultaneous classical break (e.g., a future cryptanalytic breakthrough
  against elliptic curves *and* lattices) would defeat the hybrid. This is
  considered low-probability but is not zero. Pure PQ (ML-KEM-only) and
  pure classical (X25519-only) modes are intentionally **not** offered in v0.1
  to prevent users from accidentally choosing the weaker option.

---

## Out-of-scope (N1–N5)

These attacks are real, and several are catastrophic, but they are not
addressed by Qwashed. Mitigation requires other tools and operational practices.

### N1. Endpoint compromise

If the user's device runs malware, a remote-access trojan (RAT), or a
keylogger, Qwashed cannot help. Vault passphrases, decrypted plaintext,
and signing keys all become accessible to the attacker once the vault is
unlocked.

**Mitigation:** Use full-disk encryption (FileVault, LUKS), keep the OS
patched, treat suspicious attachments as hostile, and consider hardened
distributions (Tails, Qubes OS) for high-risk workflows.

### N2. Coercion of the user

No cryptographic tool can defend against a credible threat of violence,
detention, or legal compulsion to decrypt. If the user can decrypt, an
adversary with leverage over the user can force decryption.

**Mitigation:** Operational. Plausible deniability schemes are out of
scope for v0.1; consider compartmentalization (different vaults per
project, different keys per recipient) so any single coercion event
exposes the smallest possible blast radius.

### N3. Side-channel attacks against PQ implementations

Timing, cache, electromagnetic, or power side-channels against ML-KEM /
ML-DSA implementations are an active research area. Qwashed delegates
PQ operations to liboqs, which makes its own constant-time guarantees
(with documented caveats around CCA security). A side-channel break in
liboqs would partially compromise Qwashed's PQ component; the hybrid
construction would still protect against passive ciphertext recovery
but not necessarily against active adversaries with side-channel access
to the user's machine.

**Mitigation:** Run high-risk vault operations on dedicated hardware
where possible; do not run untrusted code on the same machine as the
vault.

### N4. Traffic-analysis and metadata-correlation attacks

Qwashed's audit tool produces signed reports about an organization's
network surface. The audit itself does not encrypt the user's traffic
or hide who they communicate with. The vault encrypts file contents but
leaks file count, file sizes, modification times, and recipient
fingerprints (if export is used).

**Mitigation:** Use Tor, a mixnet (Nym, Loopix-class), or PIR-based
storage for traffic-analysis-resistant communication. Pad vault entries
or use cover traffic if metadata is sensitive.

### N5. Targeted persistent on-target adversary (TAO-class)

State-of-the-art targeted adversaries with on-network presence at the
user's ISP, on the user's device, or with operational access to the
hardware supply chain are out of scope. Qwashed is hygiene, not
counter-intelligence.

**Mitigation:** This is a profession, not a tool. Engage qualified
counsel.

---

## Adversarial use of Qwashed itself

A determined adversary could run `qwashed audit` against a list of
civil-society organizations to identify which have NOT yet migrated to
post-quantum cryptography, then target archival accordingly. This risk
is unavoidable for any open-source audit tool. The net effect of
widely-deployed migration tooling is still positive: it raises the
baseline security of the entire ecosystem faster than any closed
alternative could. Qwashed accepts this tradeoff as the price of being
free, open, and equity-prioritized.

---

## Cryptographic parameter choices

| Component         | Algorithm        | Standard                  | Rationale                                                                         |
|-------------------|------------------|---------------------------|-----------------------------------------------------------------------------------|
| Classical KEM     | X25519           | RFC 7748                  | Internet-scale deployment, decade of cryptanalysis, fast on commodity hardware.   |
| PQ KEM            | ML-KEM-768       | NIST FIPS 203 (Aug 2024)  | NIST's primary recommendation; 192-bit classical / Cat-3 PQ security.             |
| Classical signing | Ed25519          | RFC 8032                  | Same as X25519: well-deployed, well-audited.                                       |
| PQ signing        | ML-DSA-65        | NIST FIPS 204 (Aug 2024)  | NIST's primary recommendation; balanced size/security; Cat-3 PQ.                  |
| KDF               | HKDF-SHA256      | RFC 5869                  | Standard, well-understood, fits FIPS 140-3 module boundaries if needed later.     |
| AEAD              | AES-256-GCM      | NIST SP 800-38D           | 256-bit key size is quantum-resistant under Grover (effective 128-bit security).  |
| Passphrase KDF    | Argon2id         | RFC 9106                  | Memory-hard, side-channel-resistant; v0.1 params: m=64 MiB, t=3, p=1.             |
| Hash              | SHA-256, SHA3-256 | FIPS 180-4, FIPS 202     | SHA-256 for HKDF; SHA3-256 for audit-log hash chain (Keccak family for diversity).|
| Canonical JSON    | RFC 8785 (JCS)   | RFC 8785                  | Deterministic serialization for reproducible signed artifacts.                    |

All choices are standardized and widely reviewed. Qwashed deliberately does
not invent new cryptography.

---

## Versioning and forward compatibility

Qwashed's HKDF info strings include a module version
(`qwashed/vault/v0.1/kem`). When v0.2 introduces a new algorithm
selection (for example, swapping ML-KEM-768 for a successor in response to
T4-class cryptanalysis), the info string changes (`qwashed/vault/v0.2/kem`),
so v0.1 and v0.2 vault entries are bit-incompatible by construction. This
prevents an adversary from forcing a downgrade attack between versions.

Vault on-disk format includes an explicit version field; older entries can
be read by newer Qwashed releases until a deprecation window expires (one
major version after introduction, with `qwashed vault upgrade` providing
an explicit re-encryption path).

---

## How to challenge Qwashed's assumptions

This threat model is a living document. If you believe an adversary class
is misclassified, a parameter choice is wrong, or a defense is overstated,
please open a discussion or submit a pull request. Cryptographic threat
models age quickly; assume this one will need revision before v1.0.
