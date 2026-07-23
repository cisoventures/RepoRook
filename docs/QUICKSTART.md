# RepoRook five-minute onboarding

This path takes a project from “I do not know security” to deterministic scan evidence and a safe, approval-based fix conversation. Node.js 20 or later is required. A first-time scanner download may add a few minutes.

## Fastest path: ask your coding agent

Paste this into Claude Code, Codex, Cursor, GitHub Copilot, or Gemini CLI from the project you want to check:

> Set up RepoRook for this project. First run `npx --yes reporook@latest doctor .` and explain any missing scanners. Ask before installing system software. When coverage is ready, run `npx --yes reporook@latest scan . --require-scanners`. Explain the highest-risk result in plain English and propose one minimal fix, but do not edit files until I approve. After an approved fix, run the relevant tests and `npx --yes reporook@latest verify FINDING_ID . --require-scanners`. Treat incomplete coverage as inconclusive.

RepoRook supplies scanner evidence; your agent supplies contextual reasoning. The agent must keep those two kinds of conclusions separate.

## Terminal path

### 1. Check what your project needs

```bash
npx --yes reporook@latest doctor .
```

If anything is missing, print platform-specific installation commands:

```bash
npx --yes reporook@latest setup
```

`setup` does not install anything. Review and run only the commands for scanners that `doctor` marked as needed, then rerun `doctor`. Projects with OSV-supported dependency files may need OSV-Scanner in addition to the source, secret, Node, or Python scanners.

### 2. Run the gate

```bash
npx --yes reporook@latest scan . --require-scanners
```

The result is deliberately simple:

- Exit `0`: coverage completed and no finding met the configured threshold.
- Exit `1`: one or more findings met the threshold. The scan worked; review the findings.
- Exit `2`: coverage or configuration failed. Do not treat the repository as safe.

### 3. Let RepoRook brief your agent

Every scan writes:

- `.reporook/findings.json` — deterministic evidence
- `.reporook/results.sarif` — GitHub-compatible results
- `.reporook/scan-receipt.json` — coverage and scanner versions
- `.reporook/agent-prompt.txt` — a copy-ready remediation prompt that requires approval before edits

Give `agent-prompt.txt` to your coding agent. It directs the agent to explain one risk at a time, propose the smallest change, wait for approval, add regression evidence, and verify the result.

To inspect one finding yourself:

```bash
npx --yes reporook@latest explain FINDING_ID
```

### 4. Verify an approved fix

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
      - uses: cisoventures/RepoRook@v0.1.1
        with:
          fail-on: high
          mode: diff
```

The Action installs pinned scanners, comments in plain English, uploads SARIF, preserves the scan receipt, and fails closed when required coverage is unavailable.

## Safety boundaries

RepoRook never silently edits code, installs system software, rotates credentials, creates tickets, or publishes advisories. A host agent may propose changes, but you approve the exact patch and the repository tests plus RepoRook verify it.
