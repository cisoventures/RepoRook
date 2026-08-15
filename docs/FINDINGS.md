# Findings and provenance

`schemas/findings.schema.json` is the deterministic contract. It records scanner execution, coverage, normalized findings, the exact scan receipt, and mandatory artifact authentication. Each finding contains both the scanner's detailed description and a deterministic `plain_summary` written for a non-specialist.

RepoRook authenticates the complete report with an HMAC that also binds the canonical repository path. Consumers in the CLI, MCP server, and local service verify it before using findings as evidence. A JSON file that merely matches the schema, a report copied from another repository, or repository-authored content without the host-local key is rejected. The key defaults to `$XDG_CACHE_HOME/reporook/artifact-auth-key` or `~/.cache/reporook/artifact-auth-key`; controlled automation can instead inject the same secret `REPOROOK_AUTH_KEY` into producer and consumer processes.

`schemas/policy-evaluation.schema.json` is the separate deterministic team decision layer. It marks each stable finding as new, existing in the reviewed baseline, actively suppressed, or below its effective global/path threshold. `schemas/baseline.schema.json` and `schemas/suppressions.schema.json` define the committed review inputs; suppressions require an owner, reason, and expiry.

In changed-file mode, `scan_receipt.scanner_scopes` records whether each adapter ran over the repository, selected changed files, explicit external targets, or no applicable target. When an invocation authorizes configured container images, `scan_receipt.external_targets` records `authorized: true` and the exact image references. Absence of that field is never evidence of authorization. This makes incremental and external execution independently reviewable. When an organization profile is active, `policy.organization_policy` records its name, repository-relative path, and content hash; the same hash contributes to `scan_receipt.config_hash`.

`schemas/agent-review.schema.json` is the stochastic sidecar. Every review names its host, source scan, finding ID, validation status, evidence, and confidence. A host agent may reject or validate a finding but may not rewrite the original artifact or claim scanner resolution.

`schemas/priorities.schema.json` is deterministic scheduling guidance derived from policy-actionable findings. It records fix-now, fix-next, and review-later items without changing severity or scanner evidence. `schemas/remediation-plan.schema.json` binds one selected finding to its fingerprint, source commit, configuration, starting scope, exact-preview requirements, approval boundary, and verification command. `schemas/remediation-proposal.schema.json` defines the exact diff and tests; `schemas/approval-receipt.schema.json` records the authenticated, repository-bound named approval that binds them.

`schemas/verification.schema.json` records deterministic scanner resolution for one finding. It preserves both scan receipts, configuration comparison, original scanner status, and any equivalent remaining finding. Functional tests are deliberately marked `not-recorded`; scanner resolution becomes a verified fix only when the focused and relevant project tests also pass.

Scanner status remains explicit when a successful per-scanner checkpoint is reused: the status reason identifies cached evidence and its age while the scan receipt retains the bound commit, configuration hash, and scanner version. Cache data is an execution optimization, not a second evidence contract, and verification never reads it.

SARIF is a projection for code-scanning interfaces. Keep the JSON report and receipt when auditability matters because SARIF cannot express every RepoRook coverage detail as a first-class field.

Dependency advisories remain one finding per advisory in JSON and SARIF. Human-facing terminal and pull-request reports group those findings by package so repeated advisories do not bury code-level risks.

OSV alias groups become one RepoRook finding even when the same flaw has CVE, GHSA, and ecosystem-specific identifiers. The complete aliases, fixed versions, ecosystem tag, and source manifest remain in the normalized evidence.

Infrastructure findings keep the Checkov rule, framework, resource, and repository-relative line range. If Checkov's local offline policy does not provide severity, RepoRook records `raw_severity: null` and uses the conservative `medium` fallback.

Container-image findings use `metadata.target_kind: container-image` and retain the exact configured image reference in `metadata.target`; Git-history secrets use `metadata.target_kind: git-history` and may retain only a safe commit hash. Neither kind gets a pretend current-file SARIF location or MCP code excerpt. Secret values are never copied into normalized evidence.
