# RepoRook

RepoRook is a free, open-source security gate for code written by people or coding agents. It combines deterministic source, secret, dependency, infrastructure, workflow, and explicitly configured container-image scans with new-finding baselines, owned expiring suppressions, path-specific policy, and exact approval receipts behind one CLI, one findings contract, one GitHub check, and thin integrations for Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, and Windsurf.

**MIT licensed · no mandatory hosted service · no telemetry · no maintainer-funded inference.** RepoRook scans the repository and only the container targets you explicitly configure, not the agents, skills, plugins, or MCP servers that produced them.

## The beginner experience

Ask your coding agent:

> Check my app before I ship. Tell me what to fix now versus later, explain the first risk in simple English, and show me the exact patch and test plan before changing anything.

RepoRook supplies deterministic evidence with a plain-English explanation for every finding. Your existing agent can validate context and propose a patch. You approve the exact change and test plan; RepoRook records a bound receipt. RepoRook and the repository tests verify it. CI remains the merge gate.

## Five-minute quick start

Requirements: Node.js 20 or later. RepoRook orchestrates Semgrep, Gitleaks, `npm audit`, `pip-audit`, OSV-Scanner, Checkov, and Trivy when applicable.

By default Semgrep downloads the public `p/default` rule bundle and runs it with metrics disabled. Set `semgrepConfig` to a pinned local rules file when you need fully offline or byte-for-byte reproducible source scans.

```bash
npx --yes reporook@latest init .
npx --yes reporook@latest doctor .
npx --yes reporook@latest setup # prints reviewed install commands; does not install
npx --yes reporook@latest integrate install . --apply
npx --yes reporook@latest scan . --require-scanners
```

`init` detects the project stack, writes a fail-closed `reporook.yml`, and keeps local evidence out of Git. It never replaces an existing configuration unless you explicitly pass `--force`.

Exit `1` means the scan worked and found a policy-actionable issue; exit `2` means coverage, configuration, or policy loading failed. Every scan writes `.reporook/priorities.json` with a deterministic fix-now/fix-next/review-later queue containing actionable findings and `.reporook/agent-prompt.txt` with the safe next step. Prepare one finding-bound workflow with `reporook plan FINDING_ID .`; record approval of its exact patch and test plan with `reporook approve FINDING_ID .`. See the [team-policy guide](docs/TEAM_POLICY.md), [guided-fix workflow](docs/GUIDED_FIX.md), and [five-minute onboarding guide](docs/QUICKSTART.md).

Exit codes are stable for CI:

- `0`: no new, unsuppressed finding met its effective threshold
- `1`: at least one policy-actionable finding met its effective threshold
- `2`: target/configuration error, required scanner error, or no completed coverage

Scanner absence never masquerades as safety. Every report says whether coverage was `complete`, `partial`, or `failed`.
Failed coverage exits `2` by default. `--allow-no-coverage` exists only for explicit diagnostic workflows where a successful process exit is more important than a security gate.

## No-code local dashboard

People who do not want to operate the CLI can run the optional self-hosted service:

```bash
npx --yes @reporook/service@latest --repo .
```

Open the private loopback URL printed in the terminal. The dashboard walks through repository setup, runs the same deterministic scanner path, explains findings in plain English, prepares finding-bound remediation plans, and records approval of an exact proposal. It binds only to `127.0.0.1`, uses a private fragment token to establish an HTTP-only session, and never changes local application files. The **Connect this repository** button guides the user through creating and installing a private GitHub App for the detected repository; RepoRook then mints one-hour tokens narrowed to that repository and can publish an exact approved proposal as a draft PR. Personal access tokens, OAuth authorization, webhooks, and organization-wide fallback are not requested. See the [service guide](docs/SERVICE.md).

## GitHub Action

```yaml
name: RepoRook
on: [pull_request]

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
      - uses: cisoventures/RepoRook@v0.8.0
        with:
          fail-on: high
          mode: diff
```

The Action installs pinned scanners, updates one PR comment with policy dispositions and the guided fix queue, uploads SARIF, preserves the full scan and priority receipts, and enforces the configured threshold after reporting.

## Detection coverage

| Risk | Scanner | Coverage |
|---|---|---|
| Risky source patterns | Semgrep | Multi-language SAST through the selected Semgrep rules |
| Exposed credentials | Gitleaks | Repository files with secret values redacted before normalization |
| Node dependencies | `npm audit` | Root `package-lock.json` |
| Python dependencies | `pip-audit` | Root requirements files, `poetry.lock`, or `uv.lock` |
| Additional dependencies | [OSV-Scanner](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/) | Go, Rust, Java, Ruby, PHP, .NET, Dart, Elixir, R, Haskell, C/C++, Yarn, pnpm, Bun, and additional Python manifests |
| Infrastructure and workflows | [Checkov](https://www.checkov.io/) | Terraform, Kubernetes, Helm, Kustomize, Dockerfiles, and GitHub Actions; built-in local policies only |
| Container packages | [Trivy](https://trivy.dev/) | Known vulnerabilities in image references explicitly listed in `containerImages` |
| Historical credentials | [Gitleaks](https://github.com/gitleaks/gitleaks) | Opt-in Git-history scan with secret values redacted before normalization |

RepoRook gives each dependency file one primary scanner: OSV-Scanner handles supported manifests that the root `npm audit` and `pip-audit` adapters do not already own, including supported manifests in nested projects. That expands monorepo and ecosystem coverage without showing the same advisory twice merely because two scanners queried it.

## Configuration

Create `reporook.yml`:

```yaml
failOn: high
outputDir: .reporook
semgrepConfig: p/default # or a pinned local Semgrep rules file
gitHistory: false # opt in only when you intend to scan past commits
containerImages: [] # explicit refs only; RepoRook never guesses or builds images
cacheEnabled: true # successful scanner checkpoints only
cacheTtlMinutes: 15 # short freshness window for changing advisories and rules
scannerRetries: 1 # retry scanner errors once; unavailable scanners are not retried
organizationPolicy: security/reporook-organization.yml # optional committed minimum policy
paths:
  - .
ignore:
  - node_modules/**
  - dist/**
requiredScanners:
  - semgrep
  - gitleaks
scanners:
  pip-audit: true
  osv-scanner: true
  checkov: true
  trivy-image: true
baseline: reporook-baseline.json
suppressions: reporook-suppressions.json
pathPolicies:
  src/auth/**: low
  src/payments/**: medium
```

Configuration is validated strictly: unknown scanner names, invalid value types, unknown keys, a scanner that is both required and disabled, and a path rule that weakens the global threshold are errors rather than silent fallbacks. Baseline and suppression files are repository-relative, reviewable JSON. Missing policy files fail safe by making findings actionable rather than hiding them.

An optional organization policy is a committed, repository-relative YAML or JSON profile. It sets a minimum global threshold, required scanners, and sensitive-path thresholds. Repository configuration may tighten those values but cannot weaken them or disable a profile-required scanner. RepoRook validates the file without following symbolic links and binds its content hash into policy evidence and the scan receipt. See [team policy](docs/TEAM_POLICY.md).

Checkov runs with uploads and external downloads disabled and ignores repository-supplied Checkov configuration. Trivy runs only when `containerImages` contains an explicit target; tags work, but immutable digest references are safer. Git-history scanning is off by default because it expands scope and runtime. See [Infrastructure, container, and history scanning](docs/INFRASTRUCTURE.md).

Successful per-scanner results are checkpointed under `.reporook/cache/` only for a clean Git commit and reused for at most 15 minutes by default. The key binds the commit, RepoRook and scanner versions, normalized configuration, and changed-file scope. Dirty relevant files, configuration or version changes, stale or malformed records, `--refresh-cache`, and `verify` all force a fresh scanner run. Errors and unavailable scanners are never cached. Use `--no-cache` for a cache-free scan or `--cache-ttl MINUTES` for a bounded one-run freshness override.

Changed-file scans plan work per adapter. Semgrep, OSV-Scanner, `npm audit`, `pip-audit`, and Checkov receive only relevant changed files or manifests; unrelated adapters are explicitly marked `not-applicable`. Gitleaks deliberately retains repository scope so a changed secret is not missed, and Trivy retains its explicit external-image scope. The receipt records every scanner scope, making faster monorepo scans auditable rather than silently narrower.

## Outputs

- `.reporook/findings.json`: deterministic normalized findings, including a jargon-free `plain_summary`
- `.reporook/findings.json#policy`: new/baseline/suppressed/below-threshold disposition without modifying scanner evidence
- `.reporook/results.sarif`: GitHub-compatible projection
- `.reporook/scan-receipt.json`: commit, configuration hash, scanner versions, and coverage
- `.reporook/priorities.json`: deterministic fix-now, fix-next, and review-later queue
- `.reporook/agent-prompt.txt`: copy-ready, approval-based instructions for any coding agent
- `.reporook/agent-review.json`: optional, separately attributed host-agent analysis
- `.reporook/remediations/FINDING_ID/plan.json`: finding- and source-scan-bound remediation requirements
- `.reporook/remediations/FINDING_ID/proposal.json`: exact diff, file list, behavior impact, and test-plan template
- `.reporook/remediations/FINDING_ID/approval.json`: durable hashes binding the approved plan, patch, files, and tests
- `.reporook/remediations/FINDING_ID/fix-prompt.txt`: copy-ready exact-preview and approval workflow
- `.reporook/verifications/FINDING_ID/verification.json`: preserved before/after scanner-resolution receipt

The v1 schemas are in [`schemas/`](schemas/). Finding IDs intentionally exclude line numbers so inserting code above a finding does not change its identity.

## Agent integrations

Install repository-local support for all six coding-agent hosts with one command:

```bash
npx --yes reporook@latest integrate install . --apply
```

Then ask your agent, “Scan this project for security vulnerabilities and explain what I should fix first.” Use `reporook integrate doctor .`, `update . --apply`, or `uninstall . --apply` for the managed lifecycle. RepoRook previews changes without `--apply`, preserves unrelated JSON configuration, and refuses to overwrite or remove user-edited content. See the [step-by-step agent setup guide](docs/AGENT_SETUP.md).

The local MCP server exposes:

- `scan_repository`
- `scan_changes`
- `prioritize_findings`
- `get_policy_status`
- `create_findings_baseline`
- `suppress_finding`
- `list_findings`
- `get_finding`
- `get_remediation_context`
- `prepare_remediation_plan`
- `verify_fix`
- `record_remediation_approval`
- `export_findings`

Run it directly:

```json
{
  "mcpServers": {
    "reporook": {
      "command": "npx",
      "args": ["--yes", "@reporook/mcp-server"]
    }
  }
}
```

Native packages live under [`adapters/`](adapters/). Every host receives the same canonical security workflow. Native security products may deepen validation, but their conclusions remain separately attributed. RepoRook scans the code those agents produce, not the agents themselves.

## Trust model

| Label | Meaning |
|---|---|
| RepoRook finding | A deterministic scanner matched evidence in this revision |
| RepoRook priority | Deterministic severity-based scheduling guidance for a reported finding |
| Team-policy disposition | Deterministic new/baseline/suppressed/below-threshold decision, kept separate from scanner evidence |
| Remediation plan | A finding- and scan-bound workflow requiring an exact patch, test plan, and approval |
| Approval receipt | Durable hashes proving which plan, patch, files, and tests a named approver accepted |
| Native-agent validated | A named host security reviewer validated context or attack path |
| Agent hypothesis | Reasoning that has not been deterministically reproduced |
| Scanner resolution passed | The original stable finding is absent after the patch |
| Fix verified | Scanner resolution, focused regression evidence, and relevant tests passed |

Run `reporook verify FINDING_ID .` after an approved patch. It preserves the baseline, writes a separate verification receipt, and exits `0` only when the original scanner completed under the same configuration and no equivalent finding remains. RepoRook does not silently apply patches, rotate credentials, create tickets, or publish advisories.

## Development

```bash
npm install
npm run check
npm run fixture:prepare
node cli/dist/index.js scan test-fixtures/vulnerable-app --require-scanners
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/SERVICE.md`](docs/SERVICE.md), [`docs/TEAM_POLICY.md`](docs/TEAM_POLICY.md), [`docs/ADAPTERS.md`](docs/ADAPTERS.md), [`docs/AGENT_SETUP.md`](docs/AGENT_SETUP.md), the [`roadmap`](docs/ROADMAP.md), and [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Project status

The repository contains the v0.8 scale-and-reliability architecture: bounded scanner checkpoints and retries, workspace-aware changed-file scans with explicit scope receipts, and hash-bound organization policy profiles that repositories may tighten but not weaken. It builds on the local no-code service and its one-repository GitHub App boundary. Remote multi-user service operation remains future work. Scanner accuracy, policy contracts, service boundaries, and host packaging remain pre-1.0 and should expand only through fixture-backed, reviewable contributions.
