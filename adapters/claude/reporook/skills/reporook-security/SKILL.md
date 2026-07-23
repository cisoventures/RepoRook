---
name: reporook-security
description: Scan application code for vulnerabilities with RepoRook, explain findings in plain English, validate likely impact, prepare minimal fixes with approval, and verify remediation. Use for repository or diff security reviews, pre-release checks, threat-model setup, vulnerability triage, security patching, or whenever a user asks whether code is safe to ship. Do not use for scanning agent, skill, plugin, or MCP supply chains.
---

# RepoRook Security

Use RepoRook as the deterministic evidence layer. Use the host's reasoning for contextual validation and remediation. Never merge those trust levels silently.

## Run the baseline

1. Prefer the RepoRook MCP tools when available. Otherwise run `reporook scan .` or `npx --yes reporook scan .`.
2. For a pull request or local change, use `scan_changes` or `reporook scan . --changed <base> --head <head>`.
3. Read `coverage_status` and every scanner status before interpreting findings.
4. If coverage is partial or failed, say which checks did not run. Never describe an incomplete scan as clean or safe.
5. Never print, copy, or place a detected secret in a prompt, report, patch, test, or log.

## Explain for a beginner

For each material finding, explain:

- **What could happen:** describe the user-visible or business consequence.
- **How someone could reach it:** identify the attacker-controlled input and sensitive operation when known.
- **How certain this is:** label it `RepoRook verified`, `native security agent validated`, or `agent hypothesis`.
- **What to do next:** propose one focused action without assuming the user understands security terminology.

Treat deterministic matches as evidence, not automatic proof of exploitability. Inspect surrounding code, authorization boundaries, configuration, and tests. If a native security reviewer such as Claude Security, Codex Security, or Cursor Security Review is available, use it for deeper validation after the RepoRook baseline and attribute its conclusions separately.

## Fix safely

1. Work on one accepted finding at a time.
2. Use `get_remediation_context` when available.
3. Explain the intended change and likely behavior impact before editing.
4. Ask for approval before applying a security patch unless the user already explicitly authorized that exact remediation.
5. Make the smallest patch that closes the identified path. Avoid unrelated refactors and never weaken another control.
6. Add a focused regression test or reproducer when feasible.
7. Do not rotate credentials, create issues, publish advisories, or change external systems without explicit authorization.

## Verify the result

1. Run the focused regression test or strongest safe reproducer.
2. Run relevant repository tests.
3. Call `verify_fix` or run `reporook verify .`.
4. Confirm the original stable finding ID or fingerprint is gone.
5. Check nearby bypasses and legitimate behavior.
6. Report separately:
   - scanner resolution;
   - tests executed and results;
   - remaining proof gaps;
   - current coverage status.

A disappeared scanner finding alone does not prove that the application is secure.

## Establish project security context

When asked to set up or improve the threat model, ask simple questions about accounts, sensitive data, administrators, payments, external integrations, and actions users must never perform. Write only user-approved answers into a root `SECURITY.md` under clear headings for assets, trust boundaries, invariants, reportable findings, and exclusions. Use nested `SECURITY.md` files only for genuinely different component boundaries.

## Preserve provenance

Keep deterministic findings in `.reporook/findings.json`. Put host-generated validation in `.reporook/agent-review.json` using the repository's agent-review schema. Do not rewrite an agent hypothesis as a RepoRook finding. CI remains the enforcement point.
