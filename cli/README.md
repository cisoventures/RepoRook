# RepoRook CLI

RepoRook is a free, deterministic, agent-agnostic security scanner for repositories. It normalizes Semgrep, Gitleaks, `npm audit`, `pip-audit`, and OSV-Scanner evidence into one plain-English JSON/SARIF contract and always reports scanner coverage.

```bash
npx --yes reporook@latest init .
npx --yes reporook@latest doctor .
npx --yes reporook@latest setup
npx --yes reporook@latest scan . --require-scanners
npx --yes reporook@latest explain FINDING_ID
npx --yes reporook@latest prioritize .
npx --yes reporook@latest plan FINDING_ID .
```

Exit code `0` means no finding met the configured threshold, `1` means findings met it, and `2` means the target/configuration failed, a required scanner failed, or no applicable scanner completed. Failed coverage is never a successful gate unless the caller explicitly supplies the unsafe diagnostic override `--allow-no-coverage`.

Every finding includes `plain_summary`, a deterministic jargon-free explanation. Dependency advisories remain individually auditable in JSON and SARIF while terminal and pull-request output groups them by package. Every scan also writes `priorities.json` and `agent-prompt.txt`. The `plan` command binds one finding to its source scan, requires an exact patch and test preview, and writes a copy-ready prompt without modifying application code.

OSV-Scanner complements the root Node and Python adapters with supported manifests for Go, Rust, Java, Ruby, PHP, .NET, Dart, Elixir, R, Haskell, C/C++, Yarn, pnpm, Bun, additional Python formats, and nested projects. RepoRook assigns overlapping root manifests to one scanner so expanded coverage does not create duplicate advisory noise.

After an approved patch and the relevant tests, run `npx --yes reporook@latest verify FINDING_ID . --require-scanners`. RepoRook preserves the baseline scan and writes a separate receipt under `.reporook/verifications/FINDING_ID/`. Exit `0` means scanner resolution passed, `1` means the finding remains, and `2` means verification is inconclusive. Scanner resolution does not replace functional tests.

The project is MIT licensed. See the [five-minute onboarding guide](https://github.com/cisoventures/RepoRook/blob/main/docs/QUICKSTART.md) for the beginner workflow, then the full repository documentation for configuration, GitHub Action, MCP, and agent-host adapters.
