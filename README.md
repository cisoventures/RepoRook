# RepoRook

RepoRook is a free, open-source security gate for code written by people or coding agents. It combines deterministic scanners behind one CLI, one findings schema, one GitHub check, and thin integrations for Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, and Windsurf.

**MIT licensed · no hosted service · no telemetry · no maintainer-funded inference.** RepoRook scans application code, not the agents, skills, plugins, or MCP servers that produced it.

## The beginner experience

Ask your coding agent:

> Check my app before I ship. Tell me what to fix now versus later, explain the first risk in simple English, and show me the exact patch and test plan before changing anything.

RepoRook supplies deterministic evidence with a plain-English explanation for every finding. Your existing agent can validate context and propose a patch. You approve the change. RepoRook and the repository tests verify it. CI remains the merge gate.

## Five-minute quick start

Requirements: Node.js 20 or later. RepoRook orchestrates Semgrep, Gitleaks, `npm audit`, `pip-audit`, and OSV-Scanner when applicable.

By default Semgrep downloads the public `p/default` rule bundle and runs it with metrics disabled. Set `semgrepConfig` to a pinned local rules file when you need fully offline or byte-for-byte reproducible source scans.

```bash
npx --yes reporook@latest init .
npx --yes reporook@latest doctor .
npx --yes reporook@latest setup # prints reviewed install commands; does not install
npx --yes reporook@latest scan . --require-scanners
```

`init` detects the project stack, writes a fail-closed `reporook.yml`, and keeps local evidence out of Git. It never replaces an existing configuration unless you explicitly pass `--force`.

Exit `1` means the scan worked and found something to review; exit `2` means coverage failed. Every scan writes `.reporook/priorities.json` with a deterministic fix-now/fix-next/review-later queue and `.reporook/agent-prompt.txt` with the safe next step. Prepare one finding-bound workflow with `reporook plan FINDING_ID .`; its exact patch and test plan still require approval. See the [guided-fix workflow](docs/GUIDED_FIX.md) and [five-minute onboarding guide](docs/QUICKSTART.md).

Exit codes are stable for CI:

- `0`: no finding met the configured threshold
- `1`: at least one finding met the threshold
- `2`: target/configuration error, required scanner error, or no completed coverage

Scanner absence never masquerades as safety. Every report says whether coverage was `complete`, `partial`, or `failed`.
Failed coverage exits `2` by default. `--allow-no-coverage` exists only for explicit diagnostic workflows where a successful process exit is more important than a security gate.

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
      - uses: cisoventures/RepoRook@v0.3.0
        with:
          fail-on: high
          mode: diff
```

The Action installs pinned scanners, updates one PR comment with the guided fix queue, uploads SARIF, preserves the full scan and priority receipts, and enforces the configured threshold after reporting.

## Detection coverage

| Risk | Scanner | Coverage |
|---|---|---|
| Risky source patterns | Semgrep | Multi-language SAST through the selected Semgrep rules |
| Exposed credentials | Gitleaks | Repository files with secret values redacted before normalization |
| Node dependencies | `npm audit` | Root `package-lock.json` |
| Python dependencies | `pip-audit` | Root requirements files, `poetry.lock`, or `uv.lock` |
| Additional dependencies | [OSV-Scanner](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/) | Go, Rust, Java, Ruby, PHP, .NET, Dart, Elixir, R, Haskell, C/C++, Yarn, pnpm, Bun, and additional Python manifests |

RepoRook gives each dependency file one primary scanner: OSV-Scanner handles supported manifests that the root `npm audit` and `pip-audit` adapters do not already own, including supported manifests in nested projects. That expands monorepo and ecosystem coverage without showing the same advisory twice merely because two scanners queried it.

## Configuration

Create `reporook.yml`:

```yaml
failOn: high
outputDir: .reporook
semgrepConfig: p/default # or a pinned local Semgrep rules file
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
```

Configuration is validated strictly: unknown scanner names, invalid value types, unknown keys, and a scanner that is both required and disabled are errors rather than silent fallbacks.

## Outputs

- `.reporook/findings.json`: deterministic normalized findings, including a jargon-free `plain_summary`
- `.reporook/results.sarif`: GitHub-compatible projection
- `.reporook/scan-receipt.json`: commit, configuration hash, scanner versions, and coverage
- `.reporook/priorities.json`: deterministic fix-now, fix-next, and review-later queue
- `.reporook/agent-prompt.txt`: copy-ready, approval-based instructions for any coding agent
- `.reporook/agent-review.json`: optional, separately attributed host-agent analysis
- `.reporook/remediations/FINDING_ID/plan.json`: finding- and source-scan-bound remediation requirements
- `.reporook/remediations/FINDING_ID/fix-prompt.txt`: copy-ready exact-preview and approval workflow
- `.reporook/verifications/FINDING_ID/verification.json`: preserved before/after scanner-resolution receipt

The v1 schemas are in [`schemas/`](schemas/). Finding IDs intentionally exclude line numbers so inserting code above a finding does not change its identity.

## Agent integrations

The local MCP server exposes:

- `scan_repository`
- `scan_changes`
- `prioritize_findings`
- `list_findings`
- `get_finding`
- `get_remediation_context`
- `prepare_remediation_plan`
- `verify_fix`
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
| Remediation plan | A finding- and scan-bound workflow requiring an exact patch, test plan, and approval |
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

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/ADAPTERS.md`](docs/ADAPTERS.md), the [`roadmap`](docs/ROADMAP.md), and [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Project status

The repository contains the complete v0.3 guided-fix beta architecture. Scanner accuracy, prioritization policy, and host packaging remain pre-1.0 and should expand only through fixture-backed, reviewable contributions.
