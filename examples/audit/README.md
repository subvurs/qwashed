# Qwashed audit examples

Each `*.yaml` here is a minimal, runnable example of an audit config
file consumed by `qwashed audit run`. They each target a small set of
public hostnames so you can experiment without a credential bundle.

```bash
# default civil-society profile
qwashed audit run examples/audit/civic_websites.yaml \
    --profile default \
    --output /tmp/civic.json \
    --html /tmp/civic.html

# stricter healthcare profile
qwashed audit run examples/audit/healthcare_endpoints.yaml \
    --profile healthcare \
    --output /tmp/healthcare.json
```

To verify the resulting signed JSON artifact:

```bash
qwashed verify /tmp/civic.json
```

## Available example configs

| File                              | Suggested profile | Notes                                    |
|-----------------------------------|-------------------|------------------------------------------|
| `civic_websites.yaml`             | `default`         | Two generic civic-society web endpoints  |
| `healthcare_endpoints.yaml`       | `healthcare`      | Medical-record server + patient portal   |
| `journalism_endpoints.yaml`       | `journalism`      | Newsroom CMS + secure drop endpoint      |
| `legal_endpoints.yaml`            | `legal`           | Law-firm mail + case-file portal         |

These configs are deliberately small: the goal is to demonstrate the
shape of the YAML, not to crawl real production infrastructure. Replace
hostnames with your own targets to run a real audit.
