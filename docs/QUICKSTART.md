# RepoRook five-minute onboarding

This path takes a project from “I do not know security” to deterministic scan evidence and a safe, approval-based fix conversation. Node.js 20 or later is required. RepoRook never installs or updates executable software; you review and perform installations yourself.

Install RepoRook explicitly before involving a coding agent:

```bash
npm install --global reporook @reporook/mcp-server @reporook/service
```

## Fastest path: ask your coding agent

Paste this into Claude Code, Codex, Cursor, GitHub Copilot, or Gemini CLI from the project you want to check:

> Use the already-installed `reporook` command to initialize this project with `reporook init .`. If `reporook`, `reporook-mcp`, or a required scanner is missing, stop and tell me exactly what is missing. Do not use `npx` and do not download, install, or update software for me. Explain the detected stack and missing scanners. Run a complete scan, explain its team-policy status, show me the fix-now/fix-next/review-later queue, and prepare a guided plan for one actionable finding. Explain it in plain English and show me the exact diff and test plan before editing. After I approve that proposal, record the approval receipt, apply only it, run the tests, and verify the original finding. Treat incomplete coverage as inconclusive.

RepoRook supplies scanner evidence; your agent supplies contextual reasoning. The agent must keep those two kinds of conclusions separate.

## Terminal path

### 1. Initialize the project

```bash
reporook init .
```

RepoRook detects supported source, dependency, infrastructure, container-build, and workflow files, creates a fail-closed `reporook.yml`, and adds `.reporook/` to `.gitignore`. It will not replace an existing configuration unless you explicitly pass `--force`.

### 2. Check what your project needs

```bash
reporook doctor .
```

If anything is missing, print platform-specific installation commands:

```bash
reporook setup
```

`setup` prints `DISPLAY ONLY — NO COMMANDS WERE RUN` and does not install anything. Review and personally run only the commands for scanners that `doctor` marked as needed, then rerun `doctor`. Projects with OSV-supported dependency files may need OSV-Scanner; infrastructure and workflow files may need Checkov. Trivy is needed only after you explicitly list a container image.

To scan a built image, add an explicit target such as `ghcr.io/example/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` under `containerImages`. To inspect secrets in past commits, set `gitHistory: true`. Neither scope is inferred automatically; see [Infrastructure, container, and history scanning](INFRASTRUCTURE.md).

### 3. Connect your coding agent

```bash
reporook integrate install . --apply
```

This installs repository-local support for Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, and Windsurf. Restart your agent, accept its repository trust prompt if you recognize the repository, then ask: “Scan this project and explain what I should fix first.” See [Agent setup](AGENT_SETUP.md) for host-specific details and update/uninstall commands.

### 4. Run the gate

```bash
reporook scan . --require-scanners
```

RepoRook resumes successful scanner work for a clean, unchanged commit for up to 15 minutes. Scanner failures are retried once and never cached. Use `--refresh-cache` when you want every scanner rerun immediately or `--no-cache` for a cache-free diagnostic scan. Relevant uncommitted files automatically disable reuse.

The GitHub Action's `mode: diff` plans work per scanner for large repositories and monorepos. Source, dependency, and infrastructure scanners receive only relevant changed files or manifests; Gitleaks retains repository scope so changed secrets are not missed. `.reporook/scan-receipt.json` records every resulting scanner scope.

The result is deliberately simple:

- Exit `0`: coverage completed and no new, unsuppressed finding met its effective threshold.
- Exit `1`: one or more policy-actionable findings met the threshold. The scan worked; review the findings.
- Exit `2`: coverage or configuration failed. Do not treat the repository as safe.

### 5. Choose and plan one fix

Every scan writes:

- `.reporook/findings.json` — deterministic evidence
- `.reporook/results.sarif` — GitHub-compatible results
- `.reporook/scan-receipt.json` — coverage and scanner versions
- `.reporook/priorities.json` — deterministic fix-now, fix-next, and review-later queue
- `.reporook/agent-prompt.txt` — a copy-ready remediation prompt that requires approval before edits

Review the queue directly:

```bash
reporook prioritize .
```

Then prepare one finding-bound workflow:

```bash
reporook plan FINDING_ID .
```

This writes `plan.json`, `proposal.json`, and `fix-prompt.txt` under `.reporook/remediations/FINDING_ID/`. Give the prompt to your coding agent and have it complete the proposal template. Before editing, it must show the exact diff, affected behavior, and focused plus relevant test commands. Your approval applies only to that displayed proposal; a changed file, dependency version, behavior, or test plan requires a new approval.

After approving the exact proposal, record it before editing:

```bash
reporook approve FINDING_ID . \
  --approved-by "your-name" \
  --reason "Reviewed the exact patch and tests"
```

To inspect one finding yourself:

```bash
reporook explain FINDING_ID
```

### 6. Verify an approved fix

After the focused test and relevant project tests pass:

```bash
reporook verify FINDING_ID . --require-scanners
```

Verification exit `0` means scanner resolution passed, exit `1` means the finding remains, and exit `2` means the result is inconclusive. The baseline is preserved and the before/after receipt is written under `.reporook/verifications/FINDING_ID/`. A disappeared finding is not called fixed when its original scanner did not complete or the configuration changed, and scanner resolution does not replace functional tests.

Verification always reruns applicable scanners; it never accepts cached evidence as proof that an approved fix worked.

## Optional: start gating only new findings

After a complete scan and deliberate review, create a committed baseline with `reporook baseline .`. Temporarily accept one finding with `reporook suppress FINDING_ID . --owner OWNER --reason REASON --expires DATE`. Suppressions always expire and never mean fixed. See [Team policy](TEAM_POLICY.md) before enabling either workflow.

Organizations can also commit a minimum profile and reference it with `organizationPolicy: security/reporook-organization.yml`. A repository may tighten but never weaken its threshold, required scanners, or sensitive-path rules. The profile hash is recorded with the scan evidence; see [Team policy](TEAM_POLICY.md#enforce-an-organization-minimum).

## Add the pull-request gate

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
      - uses: cisoventures/RepoRook@v0.9.2
        with:
          fail-on: high
          mode: diff
```

The Action installs pinned scanners, comments with policy dispositions and the guided fix queue, uploads SARIF, preserves scan and priority receipts, and fails closed when required coverage is unavailable.

## Safety boundaries

RepoRook never silently edits code, installs system software, rotates credentials, creates tickets, or publishes advisories. A host agent may propose changes, but you approve the exact patch and the repository tests plus RepoRook verify it.
