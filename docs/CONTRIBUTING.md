# Contributing to Qwashed

Qwashed is in pre-release. Contributions are welcome and will be tracked
here and in the changelog.

## Quick start

```bash
git clone https://github.com/qwashed/qwashed.git
cd qwashed
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,full]"
pytest
ruff check qwashed tests
mypy qwashed
```

## Ground rules

1. **Cryptography:** Do not roll your own. All cryptographic primitives must
   come from `cryptography`, `liboqs-python`, or `argon2-cffi`. New algorithms
   require a documented standardization rationale and review.

2. **Fail-closed:** Every error path must either re-raise, return an explicit
   failure value with logging, or signal failure via Pydantic. No silent
   best-effort success. PRs that catch broad `Exception` and log a warning will
   be rejected.

3. **Determinism:** Code that produces signed artifacts must be deterministic
   under `--deterministic` mode. Time, randomness, and ordering must be
   parameterized so they can be frozen in tests.

4. **No telemetry:** No part of Qwashed may make a network connection that the
   user did not explicitly request. CI runs the test suite with
   network access disabled to enforce this.

5. **Tests first for security-critical code:** New cryptographic plumbing must
   ship with KAT vectors (when applicable), property-based tests via
   `hypothesis`, and explicit corruption-resistance tests (corrupt one component
   of a hybrid construction; verify it fails closed).

6. **Type checking:** `mypy --strict` must pass. Public APIs must have full
   type annotations.

7. **Lint:** `ruff check` must pass with no warnings on `qwashed/*`.

8. **Commit hygiene:** SPDX header in every new source file
   (`# SPDX-License-Identifier: Apache-2.0`). Conventional commits are not
   required but appreciated.

## Threat-model changes

If a contribution materially changes the threat model
(adds an in-scope adversary, shifts a defense from in-scope to out-of-scope,
or alters a parameter choice), update `THREAT_MODEL.md` in the same PR and
flag the change in the PR description.

## Profile contributions

Threat profiles in `qwashed/audit/profiles/` are a good first contribution.
A new profile must:

- Live in its own YAML file with a clear name (e.g., `journalist.yaml`).
- Cite at least one real organization, news report, or research paper that
  motivates the profile parameters.
- Not include any real organizational data or endpoint lists.
- Pass the profile-validation test (`tests/audit/test_profiles.py` — coming
  in Phase 2).

## License of contributions

By submitting a contribution, you agree that your contribution is licensed
under the project's Apache License 2.0 and that you have the right to
contribute it. We may add a more formal Contributor License Agreement (CLA)
ahead of v1.0.0 if needed for trademark or upstream-distribution reasons.

## Code of conduct

Be decent. Be honest about what you know and don't know. The downstream users
of this software include people whose physical safety depends on it
working correctly. Treat that with the seriousness it deserves.
