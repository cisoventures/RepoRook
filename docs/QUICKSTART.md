# RepoRook five-minute onboarding

This path takes a project from “I do not know security” to deterministic scan evidence and a safe, approval-based fix conversation. Node.js 20 or later is required. A first-time scanner download may add a few minutes.

## Fastest path: ask your coding agent

Paste this into Claude Code, Codex, Cursor, GitHub Copilot, or Gemini CLI from the project you want to check:

> Set up RepoRook for this project with `npx --yes reporook@latest init .`. Explain the detected stack and any missing scanners; ask before installing system software. Run a complete scan, show me the fix-now/fix-next/review-later queue, and prepare a guided plan for one finding. Explain it in plain English and show me the exact diff and test plan before editing. After I approve that proposal, apply only it, run the tests, and verify the original finding. Treat incomplete coverage as inconclusive.

RepoRook supplies scanner evidence; your agent supplies contextual reasoning. The agent must keep those two kinds of conclusions separate.

## Terminal path

### 1. Initialize the project

```bash
npx --yes reporook@latest init .
```

RepoRook detects supported source and dependency ecosystems, creates a fail-closed `reporook.yml`, and adds `.reporook/` to `.gitignore`. It will not replace an existing configuration unless you explicitly pass `--force`.

### 2. Check what your project needs

```bash
npx --yes reporook@latest doctor .
```

If anything is missing, print platform-specific installation commands:

```bash
npx --yes reporook@latest setup
```

`setup` does not install anything. Review and run only the commands for scanners that `doctor` marked as needed, then rerun `doctor`. Projects with OSV-supported dependency files may need OSV-Scanner in addition to the source, secret, Node, or Python scanners.

### 3. Run the gate

```bash
npx --yes reporook@latest scan . --require-scanners
```

The result is deliberately simple:

- Exit `0`: coverage completed and no finding met the configured threshold.
- Exit `1`: one or more findings met the threshold. The scan worked; review the findings.
- Exit `2`: coverage or configuration failed. Do not treat the repository as safe.

### 4. Choose and plan one fix

Every scan writes:

- `.reporook/findings.json` — deterministic evidence
- `.reporook/results.sarif` — GitHub-compatible results
- `.reporook/scan-receipt.json` — coverage and scanner versions
- `.reporook/priorities.json` — deterministic fix-now, fix-next, and review-later queue
- `.reporook/agent-prompt.txt` — a copy-ready remediation prompt that requires approval before edits

Review the queue directly:

```bash
npx --yes reporook@latest prioritize .
```

Then prepare one finding-bound workflow:

```bash
npx --yes reporook@latest plan FINDING_ID .
```

This writes `plan.json` and `fix-prompt.txt` under `.reporook/remediations/FINDING_ID/`. Give the prompt to your coding agent. Before editing, it must show the exact diff, affected behavior, and focused plus relevant test commands. Your approval applies only to that displayed proposal; a changed file, dependency version, behavior, or test plan requires a new approval.

To inspect one finding yourself:

```bash
npx --yes reporook@latest explain FINDING_ID
```

### 5. Verify an approved fix

After the focused test and relevant project tests pass:

```bash
npx --yes reporook@latest verify FINDING_ID . --require-scanners
```

Verification exit `0` means scanner resolution passed, exit `1` means the finding remains, and exit `2` means the result is inconclusive. The baseline is preserved and the before/after receipt is written under `.reporook/verifications/FINDING_ID/`. A disappeared finding is not called fixed when its original scanner did not complete or the configuration changed, and scanner resolution does not replace functional tests.

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
      - uses: cisoventures/RepoRook@v0.3.0
        with:
          fail-on: high
          mode: diff
```

The Action installs pinned scanners, comments with the guided fix queue, uploads SARIF, preserves scan and priority receipts, and fails closed when required coverage is unavailable.

## Safety boundaries

RepoRook never silently edits code, installs system software, rotates credentials, creates tickets, or publishes advisories. A host agent may propose changes, but you approve the exact patch and the repository tests plus RepoRook verify it.
