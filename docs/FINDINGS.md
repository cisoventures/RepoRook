# Findings and provenance

`schemas/findings.schema.json` is the deterministic contract. It records scanner execution, coverage, normalized findings, and the exact scan receipt.

`schemas/agent-review.schema.json` is the stochastic sidecar. Every review names its host, source scan, finding ID, status, evidence, and confidence. A host agent may reject or validate a finding but may not rewrite the original artifact.

SARIF is a projection for code-scanning interfaces. Keep the JSON report and receipt when auditability matters because SARIF cannot express every RepoRook coverage detail as a first-class field.
