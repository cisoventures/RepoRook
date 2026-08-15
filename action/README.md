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
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: cisoventures/RepoRook@755ff83b9d341b2b9a1cb528dd068545c1e136fc # v1.0.0 source pin
        with:
          fail-on: high
          mode: diff
          # Set true only after reviewing configured containerImages.
          allow-external-targets: false
          # Set true only after reviewing reporook-suppressions.json.
          allow-repository-suppressions: false
```

The Action runs the same deterministic CLI used locally, updates one pull-request comment with new/baseline/suppressed dispositions plus the fix queue, uploads SARIF, preserves scan and priority receipts, and fails only after reporting completes. Outputs expose `policy-actionable`, `policy-new`, and `policy-suppressed` counts for downstream jobs.

Use `semgrep-config` to select a trusted local rules file or non-default rule source at the workflow boundary. A remote selection also requires `allow-external-targets: true`; checked-in repository configuration cannot change Semgrep rules by itself.

`require-scanners` defaults to `true`, and failed coverage exits with a tool error even if configuration makes every scanner non-applicable. The Action installs checksum-verified Gitleaks, OSV-Scanner, and Trivy binaries and pins third-party Actions by commit SHA. It installs Semgrep, pip-audit, and Checkov only when the RepoRook Action release contains `action/python-scanners.requirements.txt` with pip hashes for every direct and transitive wheel. This checkout intentionally has no such lock yet, so those three scanners are not installed automatically; when they are applicable and unavailable, required coverage fails closed. `npm audit` uses the npm executable bundled with Node.js. Trivy runs only when both `containerImages` targets and the default-false `allow-external-targets` input are present. Authenticate private registries with a host-scoped Docker configuration; RepoRook does not pass generic Trivy username/password variables. Git-history scanning remains opt-in through `gitHistory: true`.

Commit `reporook-baseline.json` and `reporook-suppressions.json` when using team policy. Suppressions remain inactive unless this trusted workflow sets `allow-repository-suppressions: true` after review. An optional repository-relative `organizationPolicy` profile can enforce minimum thresholds and required scanners; local settings may tighten it but cannot weaken it, and its content hash is preserved in evidence. Malformed policy fails with exit `2`; expired suppressions are displayed and evaluated normally.

In `mode: diff`, each adapter receives only its relevant changed files or records that no work applies. Gitleaks deliberately keeps repository scope and Trivy keeps explicit external-image scope. The exact scope for every scanner is preserved in `scan_receipt.scanner_scopes`.
