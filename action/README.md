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
      - uses: cisoventures/RepoRook@v0.9.1
        with:
          fail-on: high
          mode: diff
```

The Action runs the same deterministic CLI used locally, updates one pull-request comment with new/baseline/suppressed dispositions plus the fix queue, uploads SARIF, preserves scan and priority receipts, and fails only after reporting completes. Outputs expose `policy-actionable`, `policy-new`, and `policy-suppressed` counts for downstream jobs.

`require-scanners` defaults to `true`, and failed coverage exits with a tool error even if configuration makes every scanner non-applicable. The Action installs checksum-verified Gitleaks, OSV-Scanner, and Trivy binaries and pins third-party Actions by commit SHA. It installs Semgrep, pip-audit, and Checkov only when the RepoRook Action release contains `action/python-scanners.requirements.txt` with pip hashes for every direct and transitive wheel. This checkout intentionally has no such lock yet, so those three scanners are not installed automatically; when they are applicable and unavailable, required coverage fails closed. `npm audit` uses the npm executable bundled with Node.js. Trivy runs only for explicit `containerImages` targets, and Git-history scanning remains opt-in through `gitHistory: true`.

Commit `reporook-baseline.json` and `reporook-suppressions.json` when using team policy. An optional repository-relative `organizationPolicy` profile can enforce minimum thresholds and required scanners; local settings may tighten it but cannot weaken it, and its content hash is preserved in evidence. Malformed policy fails with exit `2`; expired suppressions are displayed and evaluated normally.

In `mode: diff`, each adapter receives only its relevant changed files or records that no work applies. Gitleaks deliberately keeps repository scope and Trivy keeps explicit external-image scope. The exact scope for every scanner is preserved in `scan_receipt.scanner_scopes`.
