# Qwashed Quickstart

Get from zero to a signed audit report and a working hybrid PQ vault in
under five minutes.

> **Audience:** Anyone installing Qwashed for the first time. Assumes you
> know how to use a terminal. Does not assume you know any cryptography.

---

## 1. Install

```bash
# Recommended: install the everything-included extra
pip install "qwashed[full]"

# Or install only what you need:
pip install "qwashed[audit]"   # HNDL auditor only
pip install "qwashed[vault]"   # Hybrid PQ vault only
pip install qwashed             # Library APIs only (no CLI extras)
```

The `[vault]` extra pulls in
[`liboqs-python`](https://pypi.org/project/liboqs-python/), which wraps the
upstream [liboqs](https://github.com/open-quantum-safe/liboqs) C library.
Wheels are published for **macOS arm64** and **Linux x86_64**. On other
platforms install liboqs first:

```bash
brew install liboqs            # macOS
sudo apt install liboqs-dev    # Debian / Ubuntu (when packaged)
# Or build liboqs 0.15.x from source: https://github.com/open-quantum-safe/liboqs
```

Verify the install worked:

```bash
qwashed --version
# qwashed 0.1.0
```

---

## 2. Your first audit (60 seconds)

Audits scan your TLS endpoints for cryptography that will be broken by future
quantum computers and produce a signed migration report.

Create `my-audit.yaml`:

```yaml
targets:
  - host: example.org
    port: 443
    label: marketing-site
  - host: members.example.org
    port: 443
    label: members-portal
```

Run it under the `default` civil-society threat profile:

```bash
qwashed audit run my-audit.yaml -o audit-2026-04-30.json
```

The JSON file is signed (Ed25519) and self-verifying:

```bash
qwashed verify audit-2026-04-30.json
# qwashed verify: OK (audit-2026-04-30.json)
```

Try a stricter profile:

```bash
qwashed audit run my-audit.yaml --profile journalism -o audit-journalist.json
qwashed audit run my-audit.yaml --profile healthcare -o audit-healthcare.json
qwashed audit run my-audit.yaml --profile legal      -o audit-legal.json
```

List the bundled profiles:

```bash
qwashed audit profiles
```

For deeper coverage of the audit subcommand including HTML/PDF output,
target file format, exit codes, and how to write a custom profile, read
[`AUDIT_GUIDE.md`](AUDIT_GUIDE.md) and [`THREAT_PROFILES.md`](THREAT_PROFILES.md).

---

## 3. Your first vault (90 seconds)

The vault encrypts files locally with hybrid post-quantum cryptography
(X25519 + ML-KEM-768) and signs every operation (Ed25519 + ML-DSA-65). No
cloud, no account.

```bash
qwashed vault init
# Passphrase: ******
# Confirm passphrase: ******
# Vault initialized at /Users/you/.qwashed
```

> **Write your passphrase down on paper.** There is no recovery.

Add a file:

```bash
qwashed vault put briefing.pdf --name "client-A intake briefing 2026-04-30"
# ULID: 01HZQK7M8X9N4Y5R6S7T8U9V0W
```

List, retrieve, verify:

```bash
qwashed vault list
qwashed vault get 01HZQK7M8X9N4Y5R6S7T8U9V0W -o briefing-recovered.pdf
qwashed vault verify
# vault: 1 entries, audit chain OK, all signatures valid
```

For the full vault flow including multi-recipient export, civil-society
threat scenarios, Argon2id parameter overrides, and tamper-response
runbooks, read [`VAULT_GUIDE.md`](VAULT_GUIDE.md).

---

## 4. Verify a release

When you download Qwashed wheels or sdists from a third-party mirror,
verify them against the project's release-signing key before trusting
the install. See [`VERIFY_RELEASE.md`](VERIFY_RELEASE.md).

---

## 5. Where next

| If you want to…                                  | Read                                  |
|--------------------------------------------------|---------------------------------------|
| Audit your organization's network surface        | [`AUDIT_GUIDE.md`](AUDIT_GUIDE.md)    |
| Store sensitive material in a hybrid PQ vault    | [`VAULT_GUIDE.md`](VAULT_GUIDE.md)    |
| Customize threat-profile scoring for your org    | [`THREAT_PROFILES.md`](THREAT_PROFILES.md) |
| Understand what Qwashed protects against         | [`../THREAT_MODEL.md`](../THREAT_MODEL.md) |
| Report a security issue                          | [`SECURITY.md`](SECURITY.md)          |
| Verify a downloaded release                      | [`VERIFY_RELEASE.md`](VERIFY_RELEASE.md) |
| Contribute code, profiles, or docs               | [`CONTRIBUTING.md`](CONTRIBUTING.md)  |

---

## Common first-run problems

**`qwashed: command not found`** — your shell does not have the install
location on `PATH`. Either re-open the terminal or run
`python -m qwashed --version` instead.

**`audit.cli.missing_yaml`** — you installed the bare `qwashed` package
without the `[audit]` extra. Run `pip install "qwashed[audit]"`.

**`liboqs` mismatch warning at runtime** — the upstream C library and
the Python wrapper sometimes have version drift. The KAT vectors in the
test suite are the authoritative behavior check; if `pytest tests/vault`
passes, the install is OK to use.

**Vault unlock fails with the wrong passphrase** — there is no recovery
path. The vault is unrecoverable without the original passphrase. This
is intentional; recovery is a coercion vector.

---

*Last updated: 2026-04-30.*
