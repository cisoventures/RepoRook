---
name: reporook-security
description: Scan application code, dependencies, infrastructure, workflows, explicit container images, and opt-in Git history with RepoRook; explain findings in plain English, validate likely impact, prepare minimal fixes with approval, and verify remediation. Use for repository or diff security reviews, pre-release checks, threat-model setup, vulnerability triage, security patching, or whenever a user asks whether code is safe to ship. Do not use for scanning agent, skill, plugin, or MCP supply chains.
---

# RepoRook Security

Use RepoRook as the deterministic evidence layer. Use the host's reasoning for contextual validation and remediation. Never merge those trust levels silently.

## Run the scan and policy gate

1. If the user asks to configure RepoRook and no configuration exists, run `reporook init .`, show what it detected, and review the generated fail-closed scanner requirements. Do not replace an existing configuration without explicit approval for `--force`.
2. Prefer the RepoRook MCP tools when available. Otherwise run `reporook scan .` or `npx --yes reporook scan .`.
3. For a pull request or local change, use `scan_changes` or `reporook scan . --changed <base> --head <head>`.
4. Read `coverage_status` and every scanner status before interpreting findings.
5. Treat exit `2` or failed coverage as a security-gate failure. If coverage is partial, say which checks did not run. Never describe an incomplete scan as clean or safe.
6. Never print, copy, or place a detected secret in a prompt, report, patch, test, or log.
7. Read `policy.summary` and each finding's policy disposition. Prioritize only `actionable` findings. Keep baseline, suppressed, and below-threshold findings visible as audit evidence without treating them as permission to edit.
8. Treat `containerImages` and `gitHistory` as explicit scope. Never add an image, trigger a build or push, enable historical scanning, or supply registry credentials without the user's intent. Prefer immutable image digests. Historical and container findings do not have current-file context; do not fabricate one.

## Manage team policy safely

1. Never create or replace a findings baseline automatically. Explain that a baseline accepts every finding in the selected scan as existing debt, show the counts and source commit, and require explicit user approval before calling `create_findings_baseline` or `reporook baseline .`.
2. Suppress one finding only when the user supplies or approves an accountable owner, a concrete reason, and a future expiry. Call `suppress_finding` or `reporook suppress FINDING_ID . --owner OWNER --reason REASON --expires DATE` only after that approval.
3. Never create an indefinite suppression, hide an expired suppression, or describe suppression as remediation. Expired suppressions are evaluated normally and should be called out.
4. Path-specific thresholds may tighten the global gate for sensitive paths. Do not use a path rule to weaken the global threshold; use an owned, expiring finding-specific suppression for accepted risk.

## Prioritize for a beginner

1. Call `prioritize_findings` or read `.reporook/priorities.json`. If only a findings artifact exists, run `reporook prioritize .`.
2. Explain the queue as **fix now**, **fix next**, and **review later**. Say that the queue covers reported findings only when scanner coverage is incomplete.
3. Start with one fix-now item. Do not bury a code or secret risk behind repeated dependency advisories; related package findings may be discussed as one upgrade while preserving every finding ID.
4. Let the user choose a different item. Severity-based ordering is deterministic guidance, not permission to edit.

## Explain for a beginner

For each material finding, explain:

- **What could happen:** describe the user-visible or business consequence.
- **How someone could reach it:** identify the attacker-controlled input and sensitive operation when known.
- **How certain this is:** label it `RepoRook verified`, `native security agent validated`, or `agent hypothesis`.
- **What to do next:** propose one focused action without assuming the user understands security terminology.

Start with the finding's deterministic `plain_summary`, then add only repository-specific context you can support with evidence. Dependency findings may be grouped by package in human-facing output, but preserve every advisory in the deterministic artifact.

For Checkov findings, identify the infrastructure resource and failed safeguard; offline checks without scanner severity normalize to medium. For container findings, identify the exact configured image and affected package. For Git-history findings, distinguish the historical commit from the current working tree and never repeat secret material.

Treat deterministic matches as evidence, not automatic proof of exploitability. Inspect surrounding code, authorization boundaries, configuration, and tests. If a native security reviewer such as Claude Security, Codex Security, or Cursor Security Review is available, use it for deeper validation after the RepoRook baseline and attribute its conclusions separately.

## Fix safely

1. Work on one accepted finding at a time.
2. Call `prepare_remediation_plan` or run `reporook plan FINDING_ID .`. Read the resulting plan and fix prompt before proposing code changes. Use `get_remediation_context` for nearby source when needed.
3. Answer the plan's validation questions and explain the intended change in plain English. Keep unsupported conclusions labeled as agent hypotheses.
4. Before editing, show the exact diff, every affected file, behavior impact, dependency version change if any, and the focused plus relevant test commands. Put that exact proposal into the generated `proposal.json` template.
5. Ask the user to approve that exact proposal. After explicit approval, call `record_remediation_approval` or run `reporook approve FINDING_ID . --approved-by NAME --reason REASON` to hash the plan, patch, file list, and tests into a durable receipt. If any bound value changes, the receipt is invalid and you must stop and ask again.
6. If the repository changed after the source scan beyond the displayed proposal, rescan and prepare a new plan before editing.
7. Make only the approved patch. Avoid unrelated refactors and never weaken another control.
8. Add the approved focused regression test or reproducer when feasible.
9. Do not rotate credentials, create issues, publish advisories, or change external systems without separate explicit authorization.

## Verify the result

1. Run the focused regression test or strongest safe reproducer.
2. Run relevant repository tests.
3. Call `verify_fix` or run `reporook verify FINDING_ID .` for the exact accepted finding.
4. Confirm verification reports the expected durable approval receipt when the change required approval. A missing receipt is a proof gap; a mismatched receipt is invalid.
5. Accept scanner resolution only when `verify_fix` says `passed`. `inconclusive` means the original scanner did not complete or the configuration changed; it is not a fix.
6. Check nearby bypasses and legitimate behavior.
7. Report separately:
   - scanner resolution;
   - tests executed and results;
   - remaining proof gaps;
   - current coverage status.

A disappeared scanner finding alone does not prove that the application is secure.

## Establish project security context

When asked to set up or improve the threat model, ask simple questions about accounts, sensitive data, administrators, payments, external integrations, and actions users must never perform. Write only user-approved answers into a root `SECURITY.md` under clear headings for assets, trust boundaries, invariants, reportable findings, and exclusions. Use nested `SECURITY.md` files only for genuinely different component boundaries.

## Preserve provenance

Keep deterministic findings in `.reporook/findings.json`. Keep reviewable team policy in `reporook-baseline.json` and `reporook-suppressions.json`. Keep exact proposal and approval evidence under `.reporook/remediations/FINDING_ID/`. Put host-generated validation in `.reporook/agent-review.json` using the repository's agent-review schema. Do not rewrite an agent hypothesis as a RepoRook finding. CI remains the enforcement point.

## Manage this host integration

When the user asks to install, update, check, or remove RepoRook's coding-agent integration, use `reporook integrate install|update|doctor|uninstall .`. Show the preview first and request approval before adding `--apply`. Never edit global agent configuration, overwrite a conflict, or delete a managed file that RepoRook reports as modified.
