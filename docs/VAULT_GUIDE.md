# Qwashed Vault Guide

> **Audience:** Civil-society IT teams, journalists, legal-aid technologists,
> organizers, clinic administrators, and anyone storing sensitive material that
> a state-scale archival adversary might be recording today and decrypting
> tomorrow.

This guide explains what `qwashed vault` is, when to use it, and how it
fits into a defense-in-depth posture for the four threat classes in
[`THREAT_MODEL.md`](../THREAT_MODEL.md). It is written for non-cryptographers.
If a passage is unclear, treat that as a documentation bug.

---

## TL;DR

`qwashed vault` is a **local-only, hybrid post-quantum file vault**. It
encrypts files at rest with X25519 + ML-KEM-768 (FIPS 203) and signs every
operation with Ed25519 + ML-DSA-65 (FIPS 204). Every read, write, list,
verify, and export operation is recorded to a hash-chained, hybrid-signed
audit log. There is no Qwashed cloud, no Qwashed account, and no telemetry.

```
qwashed vault init                          # create ~/.qwashed
qwashed vault put secret.pdf --name "client-A briefing"
qwashed vault list
qwashed vault get 01HZ...XYZ -o briefing.pdf
qwashed vault verify
qwashed vault export 01HZ...XYZ <recipient-fp> -o bundle.json
```

---

## When to use the vault

Use it for material that is sensitive enough that:

- Confidentiality must survive a future cryptographically-relevant quantum
  computer (CRQC) — i.e., the [T1 archival adversary](../THREAT_MODEL.md#t1-state-scale-archival-adversary-with-future-quantum-capability).
- Tamper-evidence matters: you want to be able to prove later that a stored
  artifact has not been silently modified.
- Compulsion of a cloud provider must not yield the data
  ([T2](../THREAT_MODEL.md#t2-cloud-provider-compulsion-adversary)).
- A backdoor in any single PQ library must not compromise the data
  ([T3](../THREAT_MODEL.md#t3-supply-chain-compromise-of-a-single-pq-library)).

Do **not** use it as your only defense if your threat model includes
[endpoint compromise (N1)](../THREAT_MODEL.md#n1-endpoint-compromise) or
[coercion (N2)](../THREAT_MODEL.md#n2-coercion-of-the-user). The vault is
hygiene, not counter-intelligence.

---

## What the vault stores

A vault is a directory (default `~/.qwashed`) with this layout:

```
~/.qwashed/
├── manifest.json                 # version, hybrid-signed
├── keys/
│   ├── identity.pub              # public X25519 + Ed25519 + ML-KEM + ML-DSA bundle
│   ├── identity.sk.enc           # passphrase-wrapped private bundle (Argon2id)
│   └── recipients/
│       └── <fingerprint>.pub     # recipients you can export to
├── entries/
│   ├── 01HZ...XYZ.bin            # hybrid-encrypted ciphertext
│   └── 01HZ...XYZ.meta.json      # signed metadata (name, timestamps, hash)
└── audit_log.jsonl               # hash-chained, hybrid-signed operation log
```

Every file is created with permissions `0o600` (owner-only) and the vault
directory is `0o700`. The vault never writes plaintext to disk; it only
exists in memory during a `get` operation.

The `audit_log.jsonl` chain is verified at every `unlock` — tampering with
any line is detected before the first vault operation runs.

---

## Quick start

### Install

```bash
pip install "qwashed[vault]"
```

The `[vault]` extra pulls in `liboqs-python` (for ML-KEM-768 / ML-DSA-65)
and `argon2-cffi` (for the passphrase KDF).

### Initialize

```bash
qwashed vault init
# Passphrase: ******
# Confirm passphrase: ******
# Vault initialized at /Users/you/.qwashed
# Identity fingerprint: a1b2c3d4...
```

The passphrase is required to unlock the vault every time. It is not stored
anywhere. Forget it and the vault is not recoverable. **Write the passphrase
down on paper and keep it somewhere physical and trusted** — the threat
model deliberately has no recovery story for forgotten passphrases.

`init` accepts non-default vault locations:

```bash
qwashed vault init --root /Volumes/EncryptedDrive/work-vault
```

### Add an entry

```bash
qwashed vault put briefing.pdf --name "client-A intake briefing 2026-04-30"
# ULID: 01HZQK7M8X9N4Y5R6S7T8U9V0W
```

The ULID is a sortable 26-character identifier. Save it; you will need it
to retrieve the entry. It is also visible via `qwashed vault list`.

### List

```bash
qwashed vault list
# 01HZQK7M8X9N4Y5R6S7T8U9V0W   1.4 MB   2026-04-30T14:22:01Z   client-A intake briefing 2026-04-30
# 01HZQR2P5Q8L3T9F1G2H3J4K5M     32 KB   2026-04-30T15:01:18Z   meeting notes
```

### Retrieve

```bash
qwashed vault get 01HZQK7M8X9N4Y5R6S7T8U9V0W -o briefing.pdf
```

### Verify

```bash
qwashed vault verify
# vault: 2 entries, audit chain OK, all signatures valid
```

`verify` checks every entry's hybrid signature, every audit-log line's
hybrid signature, and the SHA3-256 hash chain over the whole audit log.
Exit code 0 means everything is intact; 1 means signature or chain failure;
2 means a structural error (missing files, malformed JSON).

---

## Passphrase handling

The vault never accepts the passphrase as a command-line argument. There
are exactly two ways to provide it:

1. **Interactive (default):** `getpass.getpass()` reads from the controlling
   terminal. Echo is suppressed.

2. **Environment variable** (for scripted / CI use):
   ```bash
   export QWASHED_VAULT_PASSPHRASE="..."
   qwashed vault put file.bin --name "..."
   ```
   Be careful: the env var is visible to the process tree. Prefer
   interactive entry on shared systems.

There is intentionally no `--passphrase` flag. CLI arguments end up in
shell history, in `ps` listings, and in container logs; the security
review checklist (build plan §11.5) forbids them.

---

## Civil-society scenarios

### Scenario A: Journalist storing source materials

**Goal:** Encrypt notes and recordings from a sensitive interview so that
even if the laptop is seized and ciphertext is exfiltrated, a state
archival adversary recording today cannot decrypt them in 2035 with a CRQC.

```bash
qwashed vault init --root ~/work/source-A-vault
export QWASHED_VAULT_PASSPHRASE="$(pass show vaults/source-A)"
qwashed vault put interview-recording.m4a \
    --name "Source-A interview, redacted, 2026-04-30"
qwashed vault put interview-notes.md \
    --name "Notes — Source-A 2026-04-30"
```

Operational hygiene:

- Keep this vault on an encrypted external drive that is unmounted when not
  in use. Hybrid-encryption protects ciphertext-at-rest; full-disk
  encryption (FileVault, LUKS) protects against device theft from a
  decrypted-but-locked machine.
- Use one vault per source. Compromise of any single passphrase exposes the
  smallest possible blast radius.
- Run `qwashed vault verify` weekly. Tamper-evidence is a passive defense:
  it only helps if you actually look.

**This scenario does not defend against:** a hostile editor opening the
unlocked vault, a malware-compromised laptop ([N1](../THREAT_MODEL.md#n1-endpoint-compromise)),
or coercion to decrypt ([N2](../THREAT_MODEL.md#n2-coercion-of-the-user)).

### Scenario B: Legal-aid clinic intake records

**Goal:** Store client intake forms long enough for legal proceedings to
conclude (often a decade or more) without depending on a cloud SaaS that
can be subpoenaed.

```bash
qwashed vault init --root /var/legal-aid/vault
qwashed vault put intake-2026-0431.pdf --name "intake 2026-0431, immigration"
```

The clinic's case-management system can drive the vault non-interactively:

```python
import os, subprocess
os.environ["QWASHED_VAULT_PASSPHRASE"] = clinic_passphrase()  # from HSM-wrapped store
subprocess.run(
    ["qwashed", "vault", "put", str(intake_path), "--name", display_name],
    check=True,
)
```

For staff handover, use the `recipients add` / `export` flow rather than
sharing the master passphrase. Each staff member's key bundle is added as
a recipient; `qwashed vault export <ulid> <fingerprint>` produces a
bundle decryptable only by that recipient's hybrid key.

```bash
# One-time: register a new staff member's public key bundle
qwashed vault recipients add \
    --kem-pk-file alice.kem.pub \
    --sig-pk-file alice.sig.pub \
    --label "Alice (paralegal, immigration team)"

# When Alice needs the file:
qwashed vault export 01HZ...XYZ <alice-fingerprint> -o intake-for-alice.json
# Send intake-for-alice.json over any channel. Only Alice's keys decrypt it.
```

The export bundle is a signed JSON envelope — it round-trips through
`qwashed verify` to confirm it has not been tampered with in transit.

**This scenario does not defend against:** the clinic's own staff misusing
authorized access, a malware-compromised intake terminal, or compulsion of
the clinic itself.

### Scenario C: Reproductive-health-clinic patient records (coercive jurisdiction)

**Goal:** A clinic in a hostile jurisdiction wants patient records to be
retrievable by clinic staff but not by a future grand jury that subpoenas
the clinic's hosting provider. The threat model includes both
[T2 (provider compulsion)](../THREAT_MODEL.md#t2-cloud-provider-compulsion-adversary)
and a credible risk that records are bulk-archived today against future
quantum decryption ([T1](../THREAT_MODEL.md#t1-state-scale-archival-adversary-with-future-quantum-capability)).

Recommended posture:

- Vault root is on local-only encrypted storage. Never sync the vault
  directory to a cloud provider.
- The passphrase is split — for example, two staff members each hold one
  half via Shamir's Secret Sharing (out of scope for v0.1; use `ssss-split`
  separately) so unlocking requires both staff present. v0.1 itself does
  not enforce this; it is operational policy.
- Use one vault per clinical site, not one global vault. Compromise of any
  single site's passphrase does not expose other sites.
- Run `qwashed vault verify` daily. The audit log is the evidence trail
  if a record was opened — every `get` operation appends a signed line.

**Crucial limitation:** if the clinic itself is compelled to decrypt under
threat of force or detention, the vault offers no protection.
[N2 (coercion)](../THREAT_MODEL.md#n2-coercion-of-the-user) is out of
scope. Plan operational practices accordingly.

### Scenario D: Organizing campaign protecting contact lists

**Goal:** Store a contact list (names, phone numbers, addresses, signed
pledges) for a labor-organizing or tenant-organizing campaign. The
adversary is an employer or landlord with potential access to legal
discovery and the ability to bulk-record any plaintext network traffic.

```bash
qwashed vault init --root ~/.local/share/campaign-vault
qwashed vault put member-list-2026-Q2.csv \
    --name "Member list, district 4, Q2-2026"
```

When a coordinator joins the campaign:

```bash
qwashed vault recipients add \
    --kem-pk-file coordinator.kem.pub \
    --sig-pk-file coordinator.sig.pub \
    --label "District-4 coordinator"

qwashed vault export 01HZ...XYZ <coordinator-fp> -o list-for-coord.json
```

Hand the bundle off in person on a USB stick if possible; if not, send via
Signal. Even if the bundle is intercepted by a future-CRQC archival
adversary, it cannot be decrypted without the coordinator's hybrid private
key.

**Note:** Membership lists are subject to recordkeeping subpoenas in many
jurisdictions. The vault protects against silent disclosure, not against
lawful compulsion. Consult counsel.

---

## Multi-recipient export

To share a file with multiple people without sharing your vault
passphrase:

```bash
# 1. Add each recipient's public bundle once.
qwashed vault recipients add --kem-pk-file alice.kem.pub --sig-pk-file alice.sig.pub --label "Alice"
qwashed vault recipients add --kem-pk-file bob.kem.pub   --sig-pk-file bob.sig.pub   --label "Bob"

# 2. List recipients to confirm.
qwashed vault recipients list
# a1b2c3d4...   Alice
# e5f6g7h8...   Bob

# 3. Export per recipient.
qwashed vault export <ulid> a1b2c3d4... -o brief-for-alice.json
qwashed vault export <ulid> e5f6g7h8... -o brief-for-bob.json
```

Each export bundle is encrypted *to that recipient's hybrid public key
bundle* and is decryptable only by them. The bundle is also signed by the
exporting vault's hybrid identity, so the recipient can prove
provenance.

The recipient runs:

```python
from qwashed.vault.store import open_export_bundle
plaintext, meta = open_export_bundle(
    bundle_path="brief-for-alice.json",
    recipient_secret_path="alice-vault-root",
    passphrase=alice_passphrase,
)
```

(A CLI wrapper for opening export bundles is on the v0.2 roadmap; in v0.1
the library API is the supported path.)

---

## Argon2id passphrase parameters

Default vault parameters: **64 MiB memory, 3 iterations, 1 lane** (OWASP
"modern device" baseline, 2024). This is appropriate for laptops and
workstations.

For low-power devices (older phones, single-board computers) you can
override at `init` time:

```python
from qwashed.vault.store import init_vault
v = init_vault(
    root="~/low-power-vault",
    passphrase=passphrase_bytes,
    memory_kib=19_456,   # 19 MiB — OWASP minimum
    time_cost=2,
    parallelism=1,
)
```

There is currently no CLI flag for these overrides — by design. Lowering
the parameters weakens passphrase brute-force resistance, and silently
allowing it via a flag would tempt copy-paste mistakes. If you need
non-default parameters, write a small Python wrapper that calls
`init_vault` and review it locally.

The fail-closed minimums are enforced in `qwashed.core.kdf`:
19 MiB memory, 2 iterations, 1 lane, 16-byte output, 16-byte salt. Any
caller passing below those raises `KeyDerivationError`.

---

## What the audit log records

Every operation appends one line to `audit_log.jsonl`:

```json
{"ts":"2026-04-30T14:22:01Z","op":"put","subject":"01HZQK7M8X9N4Y5R6S7T8U9V0W",
 "by":"a1b2c3d4...","prev_hash":"sha3-256:...",
 "ed25519_pubkey":"...","mldsa65_pubkey":"...",
 "signature_ed25519":"...","signature_mldsa65":"..."}
```

Operations recorded:

| Op            | Meaning                                                         |
|---------------|-----------------------------------------------------------------|
| `init`        | Vault was initialized                                           |
| `put`         | A new entry was added                                           |
| `get`         | An entry was decrypted (note: not the plaintext, just the ULID) |
| `verify`      | A `vault verify` was performed                                  |
| `export`      | An entry was exported to a recipient                            |
| `recipient_add` | A recipient public bundle was registered                      |

The chain is verified at every unlock. A tampered line — including a
silently deleted last line — fails verification and the vault refuses to
open.

The audit log itself does **not** record plaintext, file contents, or
passphrases. It records the *fact* that an operation happened and *which
ULID* it touched.

---

## Recovery and disaster scenarios

### "I forgot my passphrase."

There is no recovery. The vault is unrecoverable. Write the passphrase on
paper and store it physically (a safe, a sealed envelope with counsel,
etc.).

This is intentional. A recovery mechanism is a coercion vector.

### "I want to migrate to a new machine."

Copy the entire vault directory (`~/.qwashed` by default) to the new
machine. Permissions and the audit chain are preserved. You will be
prompted for the passphrase on the next operation.

```bash
rsync -av --chmod=D700,F600 ~/.qwashed/ /mnt/new-machine/.qwashed/
```

### "I think the vault directory was tampered with."

Run `qwashed vault verify`. If it returns exit code 1 (signature or chain
failure), treat the vault as compromised:

1. Do **not** continue using the vault. The tamper-evident layer caught
   something; further operations would extend the broken chain.
2. Compare the suspect vault to a known-good backup (you do have a
   backup, right?).
3. Investigate the access vector. The audit log shows when and what the
   last legitimate operation was — every line before the tamper point
   verified, every line after did not.

### "A recipient's key was compromised."

Remove the recipient and re-issue any export bundles to a new key bundle
from the same person:

```bash
# v0.1 does not yet expose a CLI `recipients remove`; remove the file
# directly:
rm ~/.qwashed/keys/recipients/<compromised-fp>.pub

# Then rotate:
qwashed vault recipients add \
    --kem-pk-file alice-2026-rotated.kem.pub \
    --sig-pk-file alice-2026-rotated.sig.pub \
    --label "Alice (rotated 2026-04-30)"

qwashed vault export <ulid> <new-alice-fp> -o brief-for-alice-rotated.json
```

Old export bundles signed by the rotated-out key remain valid for
recipients who already received them — that is the nature of
non-revocable signatures. Treat compromised material as compromised; do
not assume rotation undoes prior exposure.

---

## What the vault explicitly does NOT do

- **No cloud, no backup, no sync.** The vault is local. If you copy it
  elsewhere, that is your operational decision and outside the protection
  of the threat model.
- **No telemetry.** Verified by the network-disabled CI test job.
- **No key escrow.** No third party can decrypt the vault. There is no
  "law-enforcement mode."
- **No plausible-deniability mode.** v0.1 does not implement deniable
  encryption (e.g., Truecrypt-style hidden volumes). Coercion
  ([N2](../THREAT_MODEL.md#n2-coercion-of-the-user)) is out of scope.
- **No metadata hiding.** File counts, file sizes, and modification
  timestamps are visible to anyone who reads the vault directory. Pad
  entries or use cover storage if metadata is sensitive.
- **No protection against endpoint compromise.** A keylogger or RAT
  defeats the vault the moment the passphrase is typed.

---

## See also

- [`THREAT_MODEL.md`](../THREAT_MODEL.md) — full adversary classification
- [`docs/SECURITY.md`](SECURITY.md) — vulnerability disclosure
- [`QWASHED_BUILD_PLAN.txt`](../QWASHED_BUILD_PLAN.txt) §7.7–§7.10 —
  vault module design
- `qwashed vault --help`, `qwashed vault <subcommand> --help`

---

*Last updated: 2026-04-30 (Phase 3 release).*
