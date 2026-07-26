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
      - uses: cisoventures/RepoRook@v0.7.0
        with:
          fail-on: high
          mode: diff
```

The Action runs the same deterministic CLI used locally, updates one pull-request comment with new/baseline/suppressed dispositions plus the fix queue, uploads SARIF, preserves scan and priority receipts, and fails only after reporting completes. Outputs expose `policy-actionable`, `policy-new`, and `policy-suppressed` counts for downstream jobs.

`require-scanners` defaults to `true`, and failed coverage exits with a tool error even if configuration makes every scanner non-applicable. The Action installs exact Semgrep, Gitleaks, pip-audit, OSV-Scanner, Checkov, and Trivy versions; verifies downloaded binary checksums; and pins third-party Actions by commit SHA. `npm audit` uses the npm executable bundled with Node.js. Trivy runs only for explicit `containerImages` targets, and Git-history scanning remains opt-in through `gitHistory: true`.

Commit `reporook-baseline.json` and `reporook-suppressions.json` when using team policy. Malformed policy fails with exit `2`; expired suppressions are displayed and evaluated normally.
