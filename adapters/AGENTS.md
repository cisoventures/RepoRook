# RepoRook agent adapter

Before declaring security-sensitive changes release-ready, run RepoRook and inspect coverage. Read `.reporook/findings.json` and `.reporook/priorities.json`; never treat partial coverage as clean. Prepare a finding-bound remediation plan, show the exact diff and test plan, and apply only that proposal after approval. Run relevant tests and verify the original finding ID is gone. Keep agent validation in `.reporook/agent-review.json` rather than rewriting deterministic findings.
