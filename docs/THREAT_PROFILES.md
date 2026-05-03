# Qwashed Threat Profiles

A **threat profile** is a YAML file that tells `qwashed audit` how
severe each kind of cryptographic finding is *for your organization*.
Different organizations face different adversaries on different
timelines; a profile encodes that policy in a small, auditable file.

> **Audience:** Anyone who wants to tune Qwashed's audit scoring to
> their organization, write a custom profile, or understand why their
> finding got the severity it did.

---

## 1. The bundled profiles

Qwashed ships with four profiles. List them with:

```bash
qwashed audit profiles
```

| Profile      | When to use                                                | classical weight | archival_likelihood | "critical" cutoff |
|--------------|------------------------------------------------------------|------------------|---------------------|-------------------|
| `default`    | Generic small/medium org with no specific risk model       | 0.85             | 0.65                | 0.85              |
| `journalism` | Newsroom intake, source protection, secure-drop endpoints  | 1.00             | 0.95                | 0.75              |
| `healthcare` | Clinics, NGO field hospitals, telemedicine                 | 0.95             | 0.80                | 0.80              |
| `legal`      | Legal aid, civil-rights advocacy, asylum / refugee work    | 1.00             | 0.90                | 0.78              |

The journalism and legal profiles weight `classical` at 1.00 and have
*lower* "critical" cutoffs than `default`, so they escalate faster.
That is the intended behavior: source-protection and
attorney-client-privilege failures are not "moderate" issues even when
they would be elsewhere.

Pick one with `--profile`:

```bash
qwashed audit run my-audit.yaml --profile journalism
```

---

## 2. The YAML schema

Every profile has the same six top-level fields:

```yaml
name: <identifier>
description: >
  <multi-line free text; shown in `qwashed audit profiles`>

category_weights:
  classical: <float in [0.0, 1.0]>   # required
  hybrid_pq: <float in [0.0, 1.0]>   # required
  pq_only:   <float in [0.0, 1.0]>   # required
  unknown:   <float in [0.0, 1.0]>   # required

archival_likelihood: <float in [0.0, 1.0]>

severity_thresholds:
  info:     0.0
  low:      <float>
  moderate: <float>
  high:     <float>
  critical: <float>

aggregation: max          # or "mean"
```

All fields are required. Extra top-level keys are rejected
(`extra="forbid"` on the Pydantic model). The loader is
`yaml.safe_load`; YAML tags are not executed.

### 2.1 Field reference

**`name`** — short identifier. The CLI uses `--profile <name>` to
look up bundled profiles, so this must match the file stem if you ship
the profile under `qwashed/audit/profiles/`.

**`description`** — multi-line free text. Shown by
`qwashed audit profiles`. State the use case and the calibration
assumption (what archival timeline, what adversary, what consequence
model).

**`category_weights`** — per-category baseline exposure. The auditor
classifies every probe finding into exactly one of:

| Category    | Meaning                                                                    |
|-------------|----------------------------------------------------------------------------|
| `classical` | RSA, ECDSA, classical DH only — HNDL-vulnerable                            |
| `hybrid_pq` | Classical + PQ co-installed (e.g. `X25519MLKEM768`)                        |
| `pq_only`   | Pure PQ — theoretically future-proof but rare in 2026                      |
| `unknown`   | Probe completed but algorithm not in our table; treated worst-case         |

The weights are *not* required to sum to 1.0; they are independent
multipliers for different risk classes. They **are** required to
satisfy a domain-monotonic invariant (see §3).

**`archival_likelihood`** — your prior on whether this organization's
traffic is being archived for later decryption. Higher number → higher
score across the board.

Tuning advice (2026 baseline): 0.5–0.7 for organizations of no
particular interest; 0.7–0.9 for orgs with named adversaries; 0.9+ for
journalism / dissident / legal-aid contexts where state-level archival
is the working assumption.

**`severity_thresholds`** — five required cutoffs in `[0.0, 1.0]`,
monotonic non-decreasing. `info` is conventionally 0.0.
`severity_for(score)` walks from `critical` down and returns the first
tier whose cutoff `score` meets or exceeds.

A score below `low` is `info`; a score `>= critical` is `critical`.

**`aggregation`** — how to roll up per-target scores into one
organization-wide score:

* `max` (recommended default) — worst target sets the org severity.
  Use this when "one breach compromises the org" (newsrooms,
  legal-aid intake, patient-data systems).
* `mean` — arithmetic average of all per-finding scores. Useful for
  trend reporting where you want average posture, not worst-case.

Weighted-max and percentile aggregation are deferred to v0.2.

---

## 3. Validation invariants

The `ThreatProfile` Pydantic model enforces these rules at load time;
a profile that fails any of them is rejected with
`audit.profile.*` error codes.

1. **Required category keys.** All four of `classical`, `hybrid_pq`,
   `pq_only`, `unknown` must be present. Missing or extra keys are an
   error.

2. **Per-category bounds.** Every category weight is in `[0.0, 1.0]`.

3. **Domain monotonicity** (the core invariant):

   ```
   classical >= hybrid_pq >= pq_only
   unknown   >= hybrid_pq            # fail-closed: unknown is at least as severe as hybrid
   ```

   These reject obviously-broken profiles such as "PQ-only is more
   dangerous than classical RSA". The fail-closed `unknown`
   constraint prevents the auditor from down-scoring a finding it
   could not classify.

4. **Required severity tiers.** All of `info`, `low`, `moderate`,
   `high`, `critical` must be present.

5. **Severity thresholds in [0.0, 1.0]** and monotonic non-decreasing
   across the canonical tier order.

6. **Aggregation literal.** Only the strings `"max"` and `"mean"` are
   accepted; anything else is a schema error.

If you deviate from these, `qwashed audit run` will exit `2` with a
diagnostic before doing any network probing.

---

## 4. The scoring formula

For each finding the auditor computes:

```
score = category_weights[category] * archival_likelihood
```

bounded to `[0.0, 1.0]`. The severity tier is then the highest tier
whose threshold `score` meets or exceeds.

### Worked example (default profile)

A target negotiates pure RSA-2048 → category = `classical`, weight =
0.85. With `archival_likelihood = 0.65`:

```
score = 0.85 * 0.65 = 0.5525
```

Walking thresholds from highest:

| Tier      | Cutoff | Score >= cutoff? |
|-----------|--------|-------------------|
| critical  | 0.85   | no                |
| high      | 0.65   | no                |
| moderate  | 0.45   | **yes**           |

Severity = `moderate`.

### Same finding under `journalism`

```
score = 1.00 * 0.95 = 0.95
```

| Tier      | Cutoff | Score >= cutoff? |
|-----------|--------|-------------------|
| critical  | 0.75   | **yes**           |

Severity = `critical`.

That is the design: source-protection contexts escalate the same
finding from `moderate` to `critical`.

### Aggregation

For an audit run over many targets, `aggregate_score` is `max` (or
`mean`) of all per-target scores. `aggregate_severity` runs the same
threshold walk on the aggregate. An empty audit (zero targets)
aggregates to `0.0` / `info` by convention; the CLI will warn that
this is uninformative.

Higher-order effects — cipher strength, key length, certificate
lifetime — are intentionally **not** in the v0.1 formula. They are
easy to overweight, and the `classical / hybrid_pq / pq_only / unknown`
classification already encodes the hardest decision. v0.2 may add a
secondary "cipher-strength multiplier"; the current YAML schema is
forward-compatible.

---

## 5. Writing a custom profile

### 5.1 Start from the closest bundled profile

```bash
# Copy the closest match into your repo:
cp $(python -c 'from importlib import resources; print(resources.files("qwashed.audit.profiles") / "default.yaml")') \
   ./my-org-profile.yaml
```

Edit it in place. Keep the SPDX header.

### 5.2 Validate by loading it

```bash
qwashed audit run my-targets.yaml --profile-file ./my-org-profile.yaml
```

If the profile is malformed, you get a `audit.profile.*` error code
and the run exits `2` before any probing.

To validate the file in isolation without running an audit, the
`load_profile_from_path` API in `qwashed.audit.profile_loader` is the
single entry point both the CLI and the test suite use.

### 5.3 Calibration walkthrough

Pick numbers in this order:

1. **`archival_likelihood`** — your prior. What fraction of traffic
   to your hosts do you assume is being recorded?
2. **`category_weights["classical"]`** — *if* an adversary records
   classical-only traffic to a host like this, how bad is the
   eventual decrypt? `1.00` for source identity / privileged
   communications / lifelong patient data; `0.85` for general
   civic-tech traffic; `0.5` for marketing pages.
3. **`category_weights["unknown"]`** — set this equal to or greater
   than `classical`. Failing closed on unfamiliar algorithms is
   non-negotiable.
4. **`category_weights["hybrid_pq"]`** — what residual operational
   risk remains when the algorithm is right but the deployment may
   not be? 0.20–0.35 is typical.
5. **`category_weights["pq_only"]`** — small but non-zero. PQ-only
   without a classical fallback has interop risk in 2026.
6. **`severity_thresholds`** — pick where your organization wants
   the `critical` line, then place `high`/`moderate`/`low` to make
   the in-between tiers usable. Lower thresholds escalate faster.
7. **`aggregation`** — use `max` unless you have a specific reason to
   want averages. Civil-society profiles almost always want `max`.

### 5.4 Sanity checks before you ship

* Run the profile against a known-classical site and a known-hybrid
  site. The classical site should be `high` or `critical`; the
  hybrid site should be `low` or `moderate`. If those flip, the
  weights are inverted.
* Run with `--deterministic` and a fixed signing-key seed and diff
  the JSON output across two runs. If they differ, something in the
  profile path is non-deterministic and that is a bug; please report
  it.
* If you have a public test target, `qwashed verify` should pass on
  the signed output unconditionally.

---

## 6. Upstreaming a profile

If your profile is potentially useful to other civil-society
organizations, please consider contributing it back. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the full process; in summary:

1. Add the YAML to `qwashed/audit/profiles/<name>.yaml` with the
   SPDX header and a `description` that states the calibration
   assumption (timeline, adversary, consequence model).
2. Add a row to the table in §1 of this file.
3. Add at least one regression test that loads the profile and
   asserts the validation invariants hold (the test suite has
   helpers for this).
4. Open a pull request. Profile additions go through the same review
   as code; bundled profiles are part of the security model.

Profiles that are too organization-specific to be useful to others
should live in your own repo and be loaded with `--profile-file`.
That path is fully supported and is not a second-class citizen.

---

## 7. Where profiles fit in the audit pipeline

```
my-audit.yaml ──┐
                ├──> qwashed.audit.probe ──> ProbeResult
                │                                 │
threat profile ─┤                          classifier.py
(--profile or   │                                 │
 --profile-file)│                                 ▼
                │                            AuditFinding
                │                                 │
                └─────────> scoring.py ───────────┤
                                                  ▼
                                       AuditFinding (+score, +severity)
                                                  │
                                            roadmap.py
                                                  ▼
                                  AuditFinding (+roadmap)
                                                  │
                                          AuditReport ──> signed JSON
```

The profile only appears at the scoring stage. Probing and
classification are profile-independent; this means swapping profiles
between runs cannot change *what was observed*, only *how it was
scored*. That separation is intentional and is what makes Qwashed
audits portable across organizations.

---

## 8. References

* Scoring source: `qwashed/audit/scoring.py`
* Profile loader: `qwashed/audit/profile_loader.py`
* Profile schema: `qwashed/audit/schemas.py` (`ThreatProfile` model)
* Bundled profiles: `qwashed/audit/profiles/*.yaml`
* Higher-level audit guide: [`AUDIT_GUIDE.md`](AUDIT_GUIDE.md)
* Threat model context: [`../THREAT_MODEL.md`](../THREAT_MODEL.md)

---

*Last updated: 2026-04-30.*
