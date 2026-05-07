# Qwashed Audit Guide

> **Audience:** Civil-society IT teams, technical staff at clinics,
> newsroom security officers, legal-aid technologists, organizing
> campaign tech leads. Assumes you can run a terminal command and read
> a YAML file. Does **not** assume cryptographic background.

This guide explains what `qwashed audit` does, when to use it, how to
write the YAML config, how to read the JSON / HTML output, and how to
turn the result into a migration plan your organization can act on.

If a passage is unclear, treat that as a documentation bug.

---

## TL;DR

```bash
qwashed audit run my-targets.yaml --profile journalism -o report.json --html report.html
qwashed verify report.json                         # signature check
```

`qwashed audit` probes a list of TLS / SSH endpoints, classifies each
negotiated cipher as `classical`, `hybrid_pq`, `pq_only`, or `unknown`,
scores each finding under a civil-society threat profile, and emits a
signed JSON report (and optional HTML / PDF). The report is the input
to your post-quantum migration plan.

It does **not** scan your private keys, attempt break attempts, or send
any data anywhere except to the endpoints you list.

---

## What is HNDL, and why do you care?

**HNDL** = "Harvest Now, Decrypt Later." A state-scale archival
adversary with access to bulk traffic (a fiber tap, a compelled cloud
provider, an ISP-level interception program) is recording encrypted
internet traffic *today*, betting that a future cryptographically-
relevant quantum computer (CRQC) will let them decrypt it in the
2030s or 2040s.

When the CRQC arrives, **every connection that used RSA-2048,
RSA-3072, ECDH P-256, ECDH P-384, ECDSA P-256, or ECDSA P-384 becomes
retroactively decryptable**. Every backup. Every login. Every chat
session. Every signed legal document.

The adversary does not need a CRQC today. They need bulk recording
today. The CRQC arrives later.

`qwashed audit` tells you which of your endpoints are still using
HNDL-vulnerable cryptography so you can migrate the high-exposure
ones first.

---

## Quick start

```bash
pip install "qwashed[audit]"
```

Create a config file (`my-targets.yaml`) listing what to audit:

```yaml
targets:
  - host: example.org
    port: 443
    label: main-site

  - host: members.example.org
    port: 443
    label: members-portal

  - host: vpn.example.org
    port: 443
    label: vpn-gateway
```

Run it:

```bash
qwashed audit run my-targets.yaml -o my-audit.json --html my-audit.html
```

That produces:

- `my-audit.json` — signed canonical-JSON report (machine-readable)
- `my-audit.html` — standalone HTML report (human-readable; no JS, no
  remote assets, color-coded by severity)

Verify the signature:

```bash
qwashed verify my-audit.json
# qwashed verify: OK (my-audit.json)
```

---

## Choosing a threat profile

Five profiles ship with v0.1; pick the one that most closely describes
the consequences of a breach for your organization:

| Profile        | When to use                                                    | Classical weight | Critical threshold |
|----------------|----------------------------------------------------------------|------------------|--------------------|
| `default`      | Generic small/medium org, mixed-sensitivity traffic            | 0.85             | 0.85               |
| `journalism`   | Newsrooms, intake servers, source-protection infrastructure    | 1.00             | 0.75               |
| `healthcare`   | Clinics, telemedicine, NGO field hospitals, patient records    | 0.95             | 0.80               |
| `legal`        | Legal-aid orgs, advocacy groups, refugee/asylum legal services | 1.00             | 0.78               |

```bash
qwashed audit run my-targets.yaml --profile journalism -o report.json
```

If none fits, write your own and pass it with `--profile-file`:

```bash
qwashed audit run my-targets.yaml --profile-file ./my-profile.yaml -o report.json
```

The full profile-authoring guide is [`THREAT_PROFILES.md`](THREAT_PROFILES.md).

---

## Choosing a TLS probe backend

As of v0.2, `qwashed audit` ships three TLS probe implementations.
The default — `native` — is hand-rolled on top of the always-installed
`cryptography` core dependency and needs no extras.

```bash
qwashed audit run targets.yaml --probe native     # default; no extras needed
qwashed audit run targets.yaml --probe stdlib     # Python `ssl` module
qwashed audit run targets.yaml --probe sslyze     # sslyze (requires [audit-deep])
qwashed audit run targets.yaml --probe-timeout 8  # bound the per-handshake clock
```

| Backend  | Extras needed     | When to use                                                                                       |
|----------|-------------------|---------------------------------------------------------------------------------------------------|
| `native` | none (default)    | Air-gapped or minimal installs; civil-society teams who do not want a third-party TLS library.    |
| `stdlib` | none              | Diagnostic fallback: `ssl`-module path that exercises the OS crypto library Python is linked against. |
| `sslyze` | `[audit-deep]`    | Deeper enumeration when you also want sslyze's cipher-suite scan surface and JA3 metadata.        |

Install matrix for v0.2:

```bash
pip install qwashed                  # native TLS probe + no SSH probe
pip install "qwashed[audit-ssh]"     # adds paramiko for SSH targets
pip install "qwashed[audit-deep]"    # adds sslyze for the --probe sslyze backend
pip install "qwashed[audit]"         # meta-extra: deep + ssh (legacy v0.1 alias)
pip install "qwashed[full]"          # everything: audit + vault + report
```

The `native` probe issues exactly one ClientHello, reads the
ServerHello + Certificate (and the AES-GCM-protected
EncryptedExtensions / Certificate handshake on TLS 1.3), classifies
the negotiated key-exchange / signature algorithms, and closes the
connection. It does not enumerate cipher suites, does not retry, and
does not send anything beyond a single handshake — same posture as
the v0.1 `stdlib` and `sslyze` paths.

---

## Reading the report

A finding looks like this in the JSON:

```json
{
  "target": {
    "host": "members.example.org",
    "port": 443,
    "protocol": "tls",
    "label": "members-portal"
  },
  "probe": {
    "status": "ok",
    "protocol_version": "TLSv1.3",
    "kex_algorithm": "ECDHE-X25519",
    "sig_algorithm": "ECDSA-P256-SHA256",
    "cipher_suite": "TLS_AES_256_GCM_SHA384"
  },
  "category": "classical",
  "severity": "high",
  "score": 0.72,
  "rationale": "TLS 1.3 negotiated with classical-only key exchange (ECDHE-X25519) and signature (ECDSA-P256). Both are HNDL-vulnerable.",
  "roadmap": [
    "URGENT: enable hybrid post-quantum key exchange (X25519MLKEM768) on this endpoint.",
    "HIGH PRIORITY: migrate the certificate to a hybrid signature (Ed25519+ML-DSA-65 once supported by your CA / by ACME profiles in your stack).",
    "MODERATE: schedule re-audit in 90 days to confirm the new posture."
  ]
}
```

**Severity bins** (from the profile):

| Severity   | Meaning                                                            |
|------------|--------------------------------------------------------------------|
| `info`     | No HNDL exposure                                                   |
| `low`      | Minor exposure (e.g., PQ-only without classical fallback)          |
| `moderate` | Hybrid PQ deployed but operational gaps remain                     |
| `high`     | Classical-only or unknown cryptography on a meaningful endpoint    |
| `critical` | The threat profile considers this category unacceptable on this target |

**Aggregate severity** in the report envelope is the highest severity
across all findings (`aggregation: max` in every bundled profile —
the weakest endpoint sets the organizational severity).

Open `report.html` in a browser for a color-coded view of the same
information.

---

## Reading the score (v0.2)

v0.2 (ROADMAP §3.5) extends `score_finding` with a small, **bounded**
catalog of HNDL boosts. The base v0.1 category score (`classical` /
`hybrid_pq` / `pq_only` / `unknown` × profile weight) still does the
heavy lifting; the boosts only raise the score when the probe surfaces
specific HNDL-relevant facts.

### Boost catalog

| Trigger                                              | Boost  | Rationale                                                  |
|------------------------------------------------------|--------|------------------------------------------------------------|
| RSA public key < `rsa_minimum` (default 2048 bit)    | +0.10  | Weak RSA accelerates HNDL: shorter keys fall first.         |
| RSA public key < `rsa_strong` (default 3072 bit)     | +0.05  | Below the strong-RSA threshold; CRQC margin is thinner.     |
| ECC public key < `ecc_minimum` (default 224 bit)     | +0.05  | Weak EC keys; same HNDL acceleration argument.              |
| Cert `not_after` past `cert_lifetime_horizon` (default 2030-01-01) | +0.05 | Long-lived cert = more harvested traffic to decrypt later. |
| TLS cipher is non-AEAD (CBC-mode etc.)               | +0.05  | AEAD is the v0.2 baseline; CBC is a downgrade hint.         |

**Bounds:**

- Each individual boost is capped at **+0.10**.
- The total v0.2 contribution to a single finding is capped at **+0.20**.
  When the unclamped sum exceeds the total cap, the contributions are
  scaled proportionally so each rationale line stays ≤ its declared
  weight.
- The final score is then clamped to `[0.0, 1.0]`.

A v0.1 fixture that exposes none of these signals (e.g., the
`hybrid_pq` golden with Ed25519 + AEAD + far-future cert) gets the
same score it got in v0.1 — the v0.2 path is purely additive.

### Per-finding `--explain` flag

```bash
qwashed audit run targets.yaml --profile journalism -o report.json --explain
```

`--explain` prints a per-finding boost breakdown to stderr after the
report renders, e.g.:

```
# qwashed audit: per-finding boost breakdown (v0.2)

mail-frontend (mail.example-lawfirm.org:443)
  category=classical base=0.900 boost=+0.050 final=0.950 severity=critical
    +0.050  RSA-2048 below rsa_strong (3072)
```

The lines are read directly off `score_finding`'s rationale, so
`--explain` cannot drift from the actual scoring logic.

### Threat-profile overrides

Profile YAML may set:

```yaml
key_length_thresholds:
  rsa_minimum: 3072        # default 2048
  rsa_strong:  4096        # default 3072
  ecc_minimum: 256         # default 224
cert_lifetime_horizon: "2028-01-01"   # default 2030-01-01
enable_v02_scoring: true               # default true
```

`enable_v02_scoring: false` reproduces v0.1 scores byte-identically —
the opt-out for v0.1-pinned evidence chains. All keys are optional;
omitting them keeps the v0.2 defaults.

---

## Exit codes

| Code | Meaning                                                                  |
|------|--------------------------------------------------------------------------|
| `0`  | Audit ran, no critical findings                                          |
| `1`  | Audit ran, **at least one critical finding** — fail-fast for CI scripts  |
| `2`  | Structural error: bad config, missing profile, signing-key error, I/O    |

A common pattern in a CI pipeline:

```bash
qwashed audit run prod-endpoints.yaml --profile journalism -o latest.json
if [ $? -eq 1 ]; then
    notify-on-call "Critical HNDL finding in production"
fi
```

---

## Configuration file format

The audit config is a YAML file. Required field: `targets` (a list).
Each target has:

| Field      | Required? | Type   | Default | Notes                                     |
|------------|-----------|--------|---------|-------------------------------------------|
| `host`     | yes       | string |         | DNS name / IPv4 / IPv6 literal for network probes; for file-only protocols (PGP, S/MIME) the key owner's email or label |
| `port`     | yes       | int    |         | TCP port for network probes; `0` for file-only protocols |
| `protocol` | no        | enum   | `tls`   | `tls`, `ssh` (v0.1.x), `pgp`, `smime` (v0.2 in development) |
| `key_path` | conditional | string |       | Required for `pgp` and `smime`; relative paths resolve against the config file's directory |
| `label`    | no        | string |         | Human-readable label that appears in the report |

Example:

```yaml
targets:
  - host: civic.example.org
    port: 443
    label: main-site
  - host: api.example.org
    port: 443
    label: api-gateway
  - host: 10.0.0.5
    port: 22
    protocol: ssh
    label: bastion
```

> **SSH probing landed in v0.1.1** (ROADMAP §3.4). `ssh` targets are
> probed natively (host-key algorithm + KEX banner) and classified
> under the same HNDL framework as TLS.
>
> **PGP and S/MIME probing are in development for v0.2** (ROADMAP §3.2).
> `pgp` targets accept an OpenPGP keyring file (binary or ASCII-armored)
> and classify the primary key + first encryption subkey. `smime`
> targets accept an X.509 certificate (PEM or DER) and classify the
> public-key algorithm + signature algorithm. Both are file-only:
> Qwashed never reaches into HSMs, mobile keychains, or remote
> keyservers in v0.2; supply the key file yourself. See
> `examples/audit/email_pgp.yaml` and `examples/audit/email_smime.yaml`
> for templates.

The four bundled examples in `examples/audit/` are valid starting
points:

```bash
qwashed audit run examples/audit/civic_websites.yaml      --profile default
qwashed audit run examples/audit/journalism_endpoints.yaml --profile journalism
qwashed audit run examples/audit/healthcare_endpoints.yaml --profile healthcare
qwashed audit run examples/audit/legal_endpoints.yaml      --profile legal
```

Replace the example hostnames with your own before running for real.

---

## Civil-society scenarios

### Scenario A: Newsroom intake-server audit

**Goal:** Confirm the secure-drop endpoints, intake-form server, and
the journalists' personal mail / chat infrastructure are not
HNDL-exposed.

```yaml
# newsroom-targets.yaml
targets:
  - host: securedrop.newsroom.example
    port: 443
    label: securedrop-public
  - host: intake-form.newsroom.example
    port: 443
    label: tip-form
  - host: mail.newsroom.example
    port: 443
    label: webmail
  - host: chat.newsroom.example
    port: 443
    label: matrix-server
```

```bash
qwashed audit run newsroom-targets.yaml \
    --profile journalism \
    -o newsroom-audit-2026-04-30.json \
    --html newsroom-audit-2026-04-30.html
```

The `journalism` profile escalates classical-only findings to
critical at threshold 0.75 (vs 0.85 for default), so a newsroom
running ECDHE-X25519 + ECDSA-P256 will see those endpoints flagged
red. That is the design — source-protection consequences are
permanent.

### Scenario B: Clinic / telemedicine perimeter audit

**Goal:** Confirm patient-data servers and the telemedicine portal
are not vulnerable to bulk-archived-then-decrypted breaches that
would expose 50-year-sensitivity records (HIV status, mental health,
reproductive health).

```yaml
# clinic-targets.yaml
targets:
  - host: portal.clinic.example
    port: 443
    label: patient-portal
  - host: ehr.clinic.example
    port: 443
    label: ehr-server
  - host: telemed.clinic.example
    port: 443
    label: telemed-bridge
  - host: api.clinic.example
    port: 443
    label: insurance-bridge
```

```bash
qwashed audit run clinic-targets.yaml --profile healthcare \
    -o clinic-2026-Q2.json --html clinic-2026-Q2.html
```

Use the signed JSON as a HIPAA / GDPR documentation artifact: it is
RFC 8785 canonical (so it round-trips through `qwashed verify`
deterministically) and shows the exact algorithms negotiated, when,
and which were flagged.

### Scenario C: Legal-aid recurring perimeter audit (CI pipeline)

**Goal:** Run an audit weekly against the legal-aid clinic's external
endpoints. Fail the CI build if a critical finding appears, so a
silent regression (e.g., a load balancer flipping back to ECDHE-only
during a vendor change) is caught within the week.

`.github/workflows/qwashed-audit.yml`:

```yaml
name: weekly-pq-audit
on:
  schedule:
    - cron: "0 8 * * 1"   # Mondays 08:00 UTC
  workflow_dispatch: {}
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install "qwashed[audit]"
      - run: qwashed audit run audits/legal-targets.yaml --profile legal -o report.json --html report.html
      - if: failure()
        run: |
          echo "Critical HNDL finding"
          # Notify on-call channel here (Signal / Matrix / etc — never plaintext)
      - uses: actions/upload-artifact@v4
        with:
          name: pq-audit-${{ github.run_id }}
          path: |
            report.json
            report.html
```

The CI exit code captures the difference between "no critical
finding" (0), "critical finding" (1), and "config / signing failure"
(2), so a misconfigured target list does not silently disguise itself
as a passing build.

### Scenario D: Organizing campaign comms perimeter

**Goal:** Verify the contact-list portal, the volunteer signup form,
and the campaign's outbound mailer are not HNDL-exposed.
Membership-list disclosure has chilling-effect consequences for
labor and tenant organizing — same long-tail sensitivity profile as
journalism source-protection.

```yaml
# campaign-targets.yaml
targets:
  - host: members.union.example
    port: 443
    label: members-portal
  - host: signup.union.example
    port: 443
    label: volunteer-signup
  - host: mail.union.example
    port: 443
    label: outbound-mailer
```

Use the `legal` profile (attorney-client privilege weighting maps
well onto labor / tenant solidarity confidentiality):

```bash
qwashed audit run campaign-targets.yaml --profile legal -o campaign-audit.json
```

If the `members-portal` endpoint scores critical, prioritize moving
that to a hybrid PQ-capable load balancer first — it is the highest-
exposure surface.

---

## Migrating after the audit

Findings come with a `roadmap` — an ordered list of remediation
steps tagged by urgency:

```
URGENT: enable hybrid post-quantum key exchange (X25519MLKEM768) on this endpoint.
HIGH PRIORITY: migrate the certificate signature ...
MODERATE: schedule re-audit in 90 days ...
```

The `roadmap[0]` urgency tag always matches the scored severity. A
common workflow:

1. Sort findings by severity (`critical` first).
2. Take `roadmap[0]` from each, in order, as the work plan.
3. Re-audit after each batch. The signed report is your evidence
   that the migration moved the needle.

For the algorithm-by-algorithm migration map (which classical
primitive maps to which hybrid replacement, and which crypto
libraries support which today), see the
[NIST PQC migration roadmap](https://csrc.nist.gov/projects/post-quantum-cryptography)
and the IETF
[hybrid PQ TLS draft](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/).
Qwashed deliberately does not invent its own migration map; it points
at the standard ones.

---

## Reproducibility and `--deterministic`

For legal-evidence preservation, use `--deterministic` to freeze the
timestamp ("2026-01-01T00:00:00Z"), version string ("0.1.0"), and
signing-key seed (all-zero) so two consecutive runs against the same
probe results produce **bit-identical** JSON bytes:

```bash
qwashed audit run targets.yaml --deterministic -o evidence.json
sha256sum evidence.json
# Run again later from the same input.
qwashed audit run targets.yaml --deterministic -o evidence.json
sha256sum evidence.json   # identical
```

`--deterministic` is for testing and evidence preservation. Never use
it for the canonical signed artifact your organization stores — that
should use a real signing key (`--signing-key /path/to/key`).

---

## Signing keys

By default, `qwashed audit run` generates a fresh ephemeral Ed25519
key for each run. The verifying party gets the public key from the
JSON envelope's `ed25519_pubkey` field, so signature verification
works end-to-end, but the key has no continuity between runs.

For a long-lived audit identity (e.g., "org-IT-audit-2026"):

```bash
# Generate a 32-byte raw seed once
python -c "import os; print(os.urandom(32).hex())" > org-audit-key.hex
# (Store this somewhere safe; treat it like an SSH private key.)

qwashed audit run targets.yaml \
    --signing-key org-audit-key.hex \
    -o report.json
```

The verifier then knows that all reports signed by this pubkey came
from your IT-audit identity. Pair this with reproducible build /
release-signing keys (see [`VERIFY_RELEASE.md`](VERIFY_RELEASE.md))
for end-to-end provenance.

> The audit-signing key is intentionally **classical Ed25519**, not
> hybrid Ed25519+ML-DSA-65, in v0.1. Audit reports are short-lived
> evidence (months, not decades), and the signing-key compromise
> story for a short-lived signature is dominated by operational
> security, not by future-CRQC concerns. Hybrid signing for audit
> reports is on the v0.2 roadmap.

---

## What the audit does NOT do

- **Does not scan internal endpoints** unless you list them in the
  config. There is no auto-discovery, no IP-range sweep, no DNS
  enumeration. Only what you list.
- **Does not exploit anything.** Probes negotiate the cipher in the
  normal client-mode handshake and read the server's offered set.
  No fuzzing, no break attempts, no Heartbleed-style probes.
- **Does not record traffic.** It records the *negotiated algorithm
  names* and structural protocol metadata. No payload, no headers,
  no content.
- **Does not phone home.** No telemetry, no analytics, no opt-in
  reporting. Verified by the network-disabled CI test job.
- **Does not classify private-key material.** It only reads what the
  server offers in the handshake.
- **Does not (yet) probe SSH** in v0.1. SSH support is deferred to
  v0.1.1. SSH targets in v0.1 produce `probe_unsupported` findings.

---

## See also

- [`VAULT_GUIDE.md`](VAULT_GUIDE.md) — local hybrid PQ vault
- [`THREAT_PROFILES.md`](THREAT_PROFILES.md) — how scoring works,
  how to write a custom profile
- [`../THREAT_MODEL.md`](../THREAT_MODEL.md) — full adversary
  classification (T1–T4 / N1–N5)
- [`VERIFY_RELEASE.md`](VERIFY_RELEASE.md) — verify a downloaded
  Qwashed release
- `qwashed audit --help`, `qwashed audit run --help`,
  `qwashed audit profiles`

---

*Last updated: 2026-05-06 (v0.2 §3.5 richer HNDL scoring landed).*
