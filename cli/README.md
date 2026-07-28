# RepoRook CLI

RepoRook is a free, deterministic, agent-agnostic security scanner for repositories. It normalizes Semgrep, Gitleaks, `npm audit`, `pip-audit`, OSV-Scanner, Checkov, and explicitly configured Trivy image evidence into one plain-English JSON/SARIF contract and always reports scanner coverage.

```bash
reporook init .
reporook doctor .
reporook setup
reporook integrate install . --apply
reporook scan . --require-scanners
reporook explain FINDING_ID
reporook prioritize .
reporook plan FINDING_ID .
reporook approve FINDING_ID . --approved-by NAME --reason "Reviewed exact proposal"
```

Exit code `0` means coverage completed and no new, unsuppressed finding met its effective threshold; `1` means policy-actionable findings met it; and `2` means the target/configuration/policy failed, a required scanner failed, or coverage was incomplete. Incomplete coverage is never a successful gate unless the caller explicitly supplies the unsafe diagnostic override `--allow-no-coverage`.

Every finding includes `plain_summary`, a deterministic jargon-free explanation. Dependency advisories remain individually auditable in JSON and SARIF while terminal and pull-request output groups them by package. Every scan also writes a separate policy evaluation, `priorities.json`, and `agent-prompt.txt`. `baseline` records reviewed existing findings, `suppress` requires an owner/reason/expiry, and path rules can only tighten the global threshold. The `plan` command binds one actionable finding to its source scan and writes an exact proposal template; `approve` hashes that exact plan, patch, file list, and test plan into a durable receipt without modifying application code.

OSV-Scanner complements the root Node and Python adapters with supported manifests for Go, Rust, Java, Ruby, PHP, .NET, Dart, Elixir, R, Haskell, C/C++, Yarn, pnpm, Bun, additional Python formats, and nested projects. RepoRook assigns overlapping root manifests to one scanner so expanded coverage does not create duplicate advisory noise.

Checkov automatically covers detected Terraform, Kubernetes, Helm, Kustomize, Dockerfile, and GitHub Actions files using local built-in policies with uploads and external downloads disabled. Add explicit `containerImages` entries to enable Trivy image scanning. Set `gitHistory: true` only when you intend Gitleaks to inspect past commits; normalized evidence remains redacted.

On a clean Git commit, successful per-scanner evidence is cached for 15 minutes by default and keyed by the commit, RepoRook and scanner versions, complete normalized configuration, and changed-file scope. Failed or unavailable scanners are never cached. Relevant working-tree changes disable cache reads and writes; `--refresh-cache` forces replacement, `--no-cache` disables it for one scan, and verification always runs fresh.

After an approved patch and the relevant tests, run `reporook verify FINDING_ID . --require-scanners`. RepoRook preserves the baseline scan and writes a separate receipt under `.reporook/verifications/FINDING_ID/`. Exit `0` means scanner resolution passed, `1` means the finding remains, and `2` means verification is inconclusive. Scanner resolution does not replace functional tests.

The project is MIT licensed. See the [five-minute onboarding guide](https://github.com/cisoventures/RepoRook/blob/main/docs/QUICKSTART.md) for the beginner workflow and the [agent setup guide](https://github.com/cisoventures/RepoRook/blob/main/docs/AGENT_SETUP.md) for managed Claude Code, Codex, Cursor, Copilot, Gemini, and Windsurf installation.
