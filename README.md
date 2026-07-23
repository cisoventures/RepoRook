# RepoRook

RepoRook is a free, open-source security gate for code written by people or coding agents. It combines deterministic scanners behind one CLI, one findings schema, one GitHub check, and thin integrations for Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, and Windsurf.

**MIT licensed · no hosted service · no telemetry · no maintainer-funded inference.** RepoRook scans application code, not the agents, skills, plugins, or MCP servers that produced it.

## The beginner experience

Ask your coding agent:

> Check my app before I ship. Explain anything dangerous in simple English and help me fix it safely.

RepoRook supplies deterministic evidence. Your existing agent can validate context and propose a patch. You approve the change. RepoRook and the repository tests verify it. CI remains the merge gate.

## Quick start

Requirements: Node.js 20 or later. RepoRook orchestrates Semgrep, Gitleaks, `npm audit`, and `pip-audit` when applicable.

By default Semgrep downloads the public `p/default` rule bundle and runs it with metrics disabled. Set `semgrepConfig` to a pinned local rules file when you need fully offline or byte-for-byte reproducible source scans.

```bash
npx reporook doctor
npx reporook setup
npx reporook scan .
```

Exit codes are stable for CI:

- `0`: no finding met the configured threshold
- `1`: at least one finding met the threshold
- `2`: target, configuration, or required scanner error

Scanner absence never masquerades as safety. Every report says whether coverage was `complete`, `partial`, or `failed`.

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
      - uses: cisoventures/RepoRook@main # use a release tag once published
        with:
          fail-on: high
          mode: diff
```

The Action installs pinned scanners, updates one PR comment, uploads SARIF, preserves the full scan receipt, and enforces the configured threshold after reporting.

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
```

## Outputs

- `.reporook/findings.json`: deterministic normalized findings
- `.reporook/results.sarif`: GitHub-compatible projection
- `.reporook/scan-receipt.json`: commit, configuration hash, scanner versions, and coverage
- `.reporook/agent-review.json`: optional, separately attributed host-agent analysis

The v1 schemas are in [`schemas/`](schemas/). Finding IDs intentionally exclude line numbers so inserting code above a finding does not change its identity.

## Agent integrations

The local MCP server exposes:

- `scan_repository`
- `scan_changes`
- `list_findings`
- `get_finding`
- `get_remediation_context`
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

Native packages live under [`adapters/`](adapters/). Every host receives the same canonical security workflow. Native security products may deepen validation, but their conclusions remain separately attributed.

## Trust model

| Label | Meaning |
|---|---|
| RepoRook finding | A deterministic scanner matched evidence in this revision |
| Native-agent validated | A named host security reviewer validated context or attack path |
| Agent hypothesis | Reasoning that has not been deterministically reproduced |
| Scanner resolution passed | The original stable finding is absent after the patch |
| Fix verified | Scanner resolution, focused regression evidence, and relevant tests passed |

RepoRook does not silently apply patches, rotate credentials, create tickets, or publish advisories.

## Development

```bash
npm install
npm run check
node cli/dist/index.js scan test-fixtures/vulnerable-app --require-scanners
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/ADAPTERS.md`](docs/ADAPTERS.md), and [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Project status

The repository contains the complete beta architecture. Scanner detection accuracy and host packaging should be treated as pre-1.0 and expanded through fixture-backed contributions.
