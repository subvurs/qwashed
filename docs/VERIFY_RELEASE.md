# Verifying a Qwashed Release

This document describes how to verify that a Qwashed release tarball
or wheel is genuine and unmodified before you install or run it.

> **Audience:** Anyone installing Qwashed from a third-party mirror,
> a corporate proxy, an air-gapped network, or any source other than
> the official PyPI publication. Civil-society orgs in particular
> should run release verification on every install.

There are two distinct verification flows in Qwashed; do not confuse
them:

| Flow                          | What it verifies                                   | Tool                  |
|-------------------------------|----------------------------------------------------|-----------------------|
| **Release verification**      | The wheel / sdist you downloaded is genuine        | This document         |
| **Artifact verification**     | A signed audit report or vault metadata is intact  | `qwashed verify`      |

This document is the first one. The second is covered briefly in §6.

---

## 1. What a Qwashed release is signed with

Each Qwashed release on PyPI ships with three artifacts per package
file (wheel or sdist):

```
qwashed-0.1.0.tar.gz                # the source distribution
qwashed-0.1.0.tar.gz.sha256         # SHA-256 of the file above
qwashed-0.1.0.tar.gz.sig            # Ed25519 detached signature of the .sha256 file
```

and the same triplet for each platform wheel:

```
qwashed-0.1.0-py3-none-any.whl
qwashed-0.1.0-py3-none-any.whl.sha256
qwashed-0.1.0-py3-none-any.whl.sig
```

Plus one project-wide manifest:

```
SHA256SUMS                          # `sha256 <hex>  <filename>` lines for every release file
SHA256SUMS.sig                      # Ed25519 detached signature of SHA256SUMS
```

The `.sig` files are **raw 64-byte Ed25519 signatures** over the bytes
of the corresponding `.sha256` (or `SHA256SUMS`) file. They are not
PGP envelopes; they are produced by `qwashed.core.signing.SigningKey`
using the project's release-signing key.

Hybrid Ed25519 + ML-DSA-65 release signing is on the v0.2 roadmap.
The release-key migration path is documented in
[`SECURITY.md`](SECURITY.md).

### 1.1 The project release-signing key

The Ed25519 release public key is published in three places that an
attacker would have to compromise simultaneously to forge a release:

1. The repository at `release_keys/qwashed-release.pub` (committed,
   reviewed in PRs).
2. The project's `SECURITY.md` (this repo).
3. The project's web presence (TBD — domain to be announced before
   v0.1.0 publication).

The public key is a 32-byte Ed25519 key, distributed as base64 in a
single-line file:

```
# release_keys/qwashed-release.pub
qwashed-release-key-v1 <base64-32-bytes>
```

Pin this fingerprint at first use and re-verify it from the second
channel before the next install. Key rotation events are
announced in `CHANGELOG.md` and signed by the previous key.

### v0.1.0 release-key fingerprint

| Field            | Value                                                 |
|------------------|-------------------------------------------------------|
| Algorithm        | Ed25519                                               |
| Identifier       | `qwashed-release-key-v1`                              |
| Fingerprint      | `63ca4ae93b906a13`                                    |
| Definition       | First 16 hex characters of SHA-256 over the raw 32-byte Ed25519 public key |
| Public key file  | [`release_keys/qwashed-release.pub`](../release_keys/qwashed-release.pub) |

Reproduce the fingerprint from the public key file as follows:

```bash
python3 - <<'PY'
import base64, hashlib, pathlib
line = pathlib.Path("release_keys/qwashed-release.pub").read_text().split()
pub  = base64.b64decode(line[-1])
assert len(pub) == 32, "expected raw 32-byte Ed25519 public key"
print(hashlib.sha256(pub).hexdigest()[:16])
# 63ca4ae93b906a13
PY
```

The same fingerprint is published in [`docs/SECURITY.md`](SECURITY.md)
under "Verification of releases". Cross-check both before pinning.

---

## 2. Verifying a single file

Assume you have downloaded `qwashed-0.1.0-py3-none-any.whl` from a
mirror and you want to confirm it matches the official release.

### 2.1 Step 1: check the SHA-256

```bash
# macOS
shasum -a 256 -c qwashed-0.1.0-py3-none-any.whl.sha256

# Linux
sha256sum -c qwashed-0.1.0-py3-none-any.whl.sha256
```

Expected output:

```
qwashed-0.1.0-py3-none-any.whl: OK
```

If this fails, the file is corrupted or has been tampered with —
**do not install**.

### 2.2 Step 2: verify the Ed25519 signature on the SHA-256 file

The supplied `verify_release.py` helper reads the public key, the
`.sha256`, and the `.sig`, and reports OK or FAIL:

```bash
python -m qwashed.tools.verify_release \
    --pubkey ./release_keys/qwashed-release.pub \
    --file   ./qwashed-0.1.0-py3-none-any.whl.sha256 \
    --sig    ./qwashed-0.1.0-py3-none-any.whl.sig
# verify_release: OK  qwashed-0.1.0-py3-none-any.whl.sha256
```

> **v0.1.0 status.** The `qwashed.tools.verify_release` helper ships
> with v0.1.0. If you are verifying a pre-release tarball, use the
> manual flow in §2.3.

### 2.3 Manual signature verification (no Qwashed installed)

If you cannot run any Qwashed code yet because you are still trying
to decide whether to trust this download, use a stand-alone Ed25519
verifier:

```bash
# Using `signify` (OpenBSD), `minisign`, or any Ed25519 verifier of your
# choice. The .sig is a raw 64-byte Ed25519 signature.

# Example with python3 + cryptography (system-installed, not from this download):
python3 - <<'PY'
import base64, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

pub = open("release_keys/qwashed-release.pub").read().split()[-1]
sig = open("qwashed-0.1.0-py3-none-any.whl.sig", "rb").read()
msg = open("qwashed-0.1.0-py3-none-any.whl.sha256", "rb").read()

key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub))
try:
    key.verify(sig, msg)
    print("OK")
except InvalidSignature:
    print("FAIL")
    sys.exit(1)
PY
```

Both Step 1 (SHA-256) and Step 2 (signature) must pass. Either alone
is insufficient: a SHA-256 can be regenerated by an attacker after
tampering, and a signature without a SHA-256 check leaves you trusting
the bytes of the wheel to match the signed digest.

---

## 3. Verifying every file in a release at once

For release auditors, automated mirrors, and Linux distribution
packagers, the project-wide `SHA256SUMS` is more efficient than
checking each file individually.

### 3.1 Verify SHA256SUMS itself

```bash
python -m qwashed.tools.verify_release \
    --pubkey ./release_keys/qwashed-release.pub \
    --file   ./SHA256SUMS \
    --sig    ./SHA256SUMS.sig
# verify_release: OK  SHA256SUMS
```

Or with the standalone snippet from §2.3, substituting the file paths.

### 3.2 Then verify every file listed in SHA256SUMS

```bash
shasum -a 256 -c SHA256SUMS    # macOS
sha256sum -c SHA256SUMS        # Linux
```

Both must complete without `FAIL` or `BAD signature` lines.

---

## 4. What this verification proves

| Threat                                                      | Defended by                |
|-------------------------------------------------------------|----------------------------|
| Mirror substituted a malicious wheel for the real one       | Yes — signature mismatch   |
| In-flight tampering between mirror and your machine         | Yes — SHA-256 mismatch     |
| Bit rot / corruption during download                        | Yes — SHA-256 mismatch     |
| Compromise of the project's release-signing key             | **No** — re-key required   |
| Malicious code intentionally committed to the repository    | **No** — review required   |
| Vulnerability in an upstream dependency (e.g. liboqs)       | **No** — out of scope      |
| Endpoint malware modifying the wheel after extraction       | **No** — see THREAT_MODEL  |

Release verification is a **single-link** integrity check: the byte
sequence we signed is the byte sequence you have. It is **not** a
trustworthiness check on the code itself.

---

## 5. Air-gapped install workflow

If you are installing on a machine that has never been online (or
will never be online again):

1. On a trusted online machine, download:
   * The wheel(s) for your platform and Python version.
   * The matching `.sha256` and `.sig` files for each.
   * `SHA256SUMS` and `SHA256SUMS.sig`.
   * `release_keys/qwashed-release.pub` from the repository.

2. Verify all of the above on the trusted machine using §3.

3. Burn the verified files to a write-once medium (DVD-R, signed USB).

4. On the air-gapped machine, repeat §3 against the same files using
   the same public key, then install:
   ```bash
   pip install --no-index --find-links ./qwashed-release-bundle/ qwashed
   ```

5. Confirm the install:
   ```bash
   qwashed --version
   ```

If the version number, SHA-256, and signature all match across both
machines, your install is verified end-to-end.

---

## 6. Verifying a signed Qwashed artifact

This is a **different** flow from release verification. Once Qwashed
is installed and you have produced a signed audit report, vault
audit-log line, or vault entry metadata, verify it with:

```bash
qwashed verify <artifact.json>
```

This:

* Reads the embedded `signature_ed25519` and `ed25519_pubkey` fields.
* Strips the signature, canonicalizes the rest with RFC 8785, and
  verifies the Ed25519 signature against the embedded public key.

Exit codes:

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| 0    | Signature valid                                                  |
| 1    | Signature mismatch (artifact tampered or wrong public key)       |
| 2    | Structural / I/O / parse error (artifact unreadable or malformed)|

`qwashed verify` does **not** check the embedded public key against
any trust root — it just verifies that the artifact was signed by
*whoever held the private key*. For audit reports produced internally,
this is sufficient. For artifacts received from third parties, verify
the public key separately (e.g. by comparing against a fingerprint
the third party published through a second channel).

This works for every Qwashed artifact uniformly:

```bash
qwashed verify audit-2026-04-30.json           # audit report
qwashed verify ~/.qwashed/log.jsonl            # vault audit-log line
qwashed verify ~/.qwashed/entries/<ULID>.json  # vault entry metadata
```

---

## 7. What to do if verification fails

1. **Do not install.** Move the file out of any auto-install path.
2. Re-download from a different mirror or directly from PyPI.
3. Re-verify against the same public key.
4. If the second download also fails verification, report the
   failure via `docs/SECURITY.md` (encrypted disclosure channel).
   Do not open a public issue — a verification failure can mean a
   live supply-chain attack, and a public issue gives the attacker
   confirmation.

If the public key itself is the problem (the file we gave you does
not match the fingerprint published in `SECURITY.md` or on the
project's web presence), treat the entire repository checkout as
suspect and re-clone from a known-good source.

---

## 8. References

* Top-level CLI verifier: `qwashed/cli.py` (`_verify` function)
* Release-time signing tooling: `qwashed/tools/` (v0.1.0+)
* Underlying Ed25519 implementation: `qwashed/core/signing.py`
* Canonical-JSON spec: RFC 8785
* Disclosure channels and key publication: [`SECURITY.md`](SECURITY.md)

---

*Last updated: 2026-04-30.*
