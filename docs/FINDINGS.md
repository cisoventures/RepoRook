# Findings and provenance

`schemas/findings.schema.json` is the deterministic contract. It records scanner execution, coverage, normalized findings, and the exact scan receipt. Each finding contains both the scanner's detailed description and a deterministic `plain_summary` written for a non-specialist.

`schemas/agent-review.schema.json` is the stochastic sidecar. Every review names its host, source scan, finding ID, validation status, evidence, and confidence. A host agent may reject or validate a finding but may not rewrite the original artifact or claim scanner resolution.

`schemas/priorities.schema.json` is deterministic scheduling guidance derived from findings. It records fix-now, fix-next, and review-later items without changing severity or scanner evidence. `schemas/remediation-plan.schema.json` binds one selected finding to its fingerprint, source commit, configuration, starting scope, exact-preview requirements, approval boundary, and verification command.

`schemas/verification.schema.json` records deterministic scanner resolution for one finding. It preserves both scan receipts, configuration comparison, original scanner status, and any equivalent remaining finding. Functional tests are deliberately marked `not-recorded`; scanner resolution becomes a verified fix only when the focused and relevant project tests also pass.

SARIF is a projection for code-scanning interfaces. Keep the JSON report and receipt when auditability matters because SARIF cannot express every RepoRook coverage detail as a first-class field.

Dependency advisories remain one finding per advisory in JSON and SARIF. Human-facing terminal and pull-request reports group those findings by package so repeated advisories do not bury code-level risks.

OSV alias groups become one RepoRook finding even when the same flaw has CVE, GHSA, and ecosystem-specific identifiers. The complete aliases, fixed versions, ecosystem tag, and source manifest remain in the normalized evidence.
