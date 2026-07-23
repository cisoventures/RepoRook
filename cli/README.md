# RepoRook CLI

RepoRook is a free, deterministic, agent-agnostic security scanner for repositories. It normalizes Semgrep, Gitleaks, `npm audit`, and `pip-audit` evidence into one plain-English JSON/SARIF contract and always reports scanner coverage.

```bash
npx reporook setup
npx reporook scan .
npx reporook explain FINDING_ID
```

Exit code `0` means no finding met the configured threshold, `1` means findings met it, and `2` means a target, configuration, or required scanner failed. A partial scan is never presented as clean.

The project is MIT licensed. See the full repository documentation for configuration, GitHub Action, MCP, and agent-host adapters.
