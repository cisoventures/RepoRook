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
      - uses: cisoventures/RepoRook@main # use a release tag once published
        with:
          fail-on: high
          mode: diff
```

The Action runs the same deterministic CLI used locally, updates one pull-request comment, uploads SARIF, preserves a scan receipt, and fails only after reporting completes.
