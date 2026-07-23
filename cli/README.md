# RepoRook CLI

RepoRook is a free, deterministic, agent-agnostic security scanner for repositories. It normalizes Semgrep, Gitleaks, `npm audit`, and `pip-audit` evidence into one plain-English JSON/SARIF contract and always reports scanner coverage.

```bash
npx --yes reporook@latest doctor .
npx --yes reporook@latest setup
npx --yes reporook@latest scan . --require-scanners
npx --yes reporook@latest explain FINDING_ID
```

Exit code `0` means no finding met the configured threshold, `1` means findings met it, and `2` means the target/configuration failed, a required scanner failed, or no applicable scanner completed. Failed coverage is never a successful gate unless the caller explicitly supplies the unsafe diagnostic override `--allow-no-coverage`.

Every finding includes `plain_summary`, a deterministic jargon-free explanation. Dependency advisories remain individually auditable in JSON and SARIF while terminal and pull-request output groups them by package. Every scan also writes `agent-prompt.txt` beside the findings, giving any coding agent a safe one-finding-at-a-time workflow with explicit approval and verification gates.

After an approved patch and the relevant tests, run `npx --yes reporook@latest verify FINDING_ID . --require-scanners`. RepoRook preserves the baseline scan and writes a separate receipt under `.reporook/verifications/FINDING_ID/`. Exit `0` means scanner resolution passed, `1` means the finding remains, and `2` means verification is inconclusive. Scanner resolution does not replace functional tests.

The project is MIT licensed. See the [five-minute onboarding guide](https://github.com/cisoventures/RepoRook/blob/main/docs/QUICKSTART.md) for the beginner workflow, then the full repository documentation for configuration, GitHub Action, MCP, and agent-host adapters.
