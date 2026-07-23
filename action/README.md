# RepoRook GitHub Action

```yaml
name: RepoRook
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - uses: cisoventures/RepoRook@v0.2.0
        with:
          fail-on: high
          mode: diff
```

The Action runs the same deterministic CLI used locally, updates one pull-request comment, uploads SARIF, preserves a scan receipt, and fails only after reporting completes.

`require-scanners` defaults to `true`, and failed coverage exits with a tool error even if configuration makes every scanner non-applicable. The Action installs exact Semgrep, Gitleaks, pip-audit, and OSV-Scanner versions, verifies downloaded Go-binary checksums, and pins third-party Actions by commit SHA. `npm audit` uses the npm executable bundled with Node.js.
