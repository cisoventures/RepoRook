# Team policy

RepoRook v0.5 keeps scanner evidence separate from team decisions. Findings remain unchanged in `.reporook/findings.json`; the adjacent `policy` object records whether each finding is actionable, already baselined, temporarily suppressed, or below the effective threshold.

## Gate only new findings

Run a complete scan and review every current finding before creating a baseline:

```bash
reporook scan . --require-scanners
reporook baseline .
```

The second command writes `reporook-baseline.json`. Commit that file. Future scans match stable fingerprints and gate only new findings; existing findings remain visible in JSON, SARIF, terminal output, and pull-request comments.

Creating or replacing a baseline is an acceptance decision, not a cleanup operation. Never create it automatically or from incomplete scanner coverage.

## Temporarily suppress one finding

Use an accountable owner, a concrete reason, and a future expiry:

```bash
reporook suppress FINDING_ID . \
  --owner security-team \
  --reason "Compensating control reviewed; replacement ships next sprint" \
  --expires 2026-08-31
```

This writes or updates `reporook-suppressions.json`. Commit the file so reviewers can audit the decision. Expired suppressions never disappear: RepoRook reports them as expired and evaluates matching findings normally. Suppression does not mean fixed.

## Tighten sensitive paths

Path rules live in `reporook.yml` and may only tighten the global threshold:

```yaml
failOn: high
baseline: reporook-baseline.json
suppressions: reporook-suppressions.json
pathPolicies:
  src/auth/**: low
  src/payments/**: medium
```

If several patterns match, RepoRook uses the strictest threshold. A path rule that would weaken `failOn` is a configuration error; accepted risk must use a finding-specific owned suppression.

## Enforce an organization minimum

An organization can commit one minimum profile, for example `security/reporook-organization.yml`:

```yaml
schemaVersion: "1.0"
name: CISO Ventures baseline
failOn: high
requiredScanners:
  - semgrep
  - gitleaks
pathPolicies:
  src/auth/**: low
  src/payments/**: medium
```

Reference it from the repository configuration:

```yaml
organizationPolicy: security/reporook-organization.yml
failOn: high
```

The profile is a floor, not an override. A repository may use a stricter global threshold, add required scanners, or add stricter path rules. It may not weaken the profile threshold, disable a profile-required scanner, or weaken a matching organization path rule. Malformed, missing, outside-repository, oversized, or symbolic-link profiles fail with exit `2`.

RepoRook accepts YAML or JSON, rejects unknown and duplicate fields, and binds the profile name, repository-relative path, and raw content hash into the effective configuration and policy evaluation. Reviewers can therefore prove which organization policy governed a scan without trusting a mutable URL or hidden service-side setting.

## Preserve exact approval evidence

`reporook plan FINDING_ID .` now writes three files under `.reporook/remediations/FINDING_ID/`:

- `plan.json` binds the finding to its source scan;
- `proposal.json` is the template for the exact unified diff, file list, behavior impact, and tests;
- `fix-prompt.txt` gives an agent the approval-safe workflow.

After reviewing the completed proposal, record the decision:

```bash
reporook approve FINDING_ID . \
  --approved-by "reviewer@example.com" \
  --reason "Reviewed the exact patch and regression plan"
```

The resulting `approval.json` hashes the plan, proposal, patch, file list, and test plan. Any change invalidates the receipt. `reporook verify` validates and attaches the receipt when present, while still reporting functional tests separately from scanner resolution.

## Exit behavior

With policy enabled, exit `1` means at least one new, unsuppressed finding meets its global or path-specific threshold. Baselined, actively suppressed, and below-threshold findings remain visible but do not fail the gate. Coverage or malformed policy evidence exits `2`.
