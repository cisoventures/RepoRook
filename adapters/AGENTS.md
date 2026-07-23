# RepoRook agent adapter

Before declaring security-sensitive changes release-ready, run RepoRook and inspect coverage. Read `.reporook/findings.json`; never treat partial coverage as clean. Explain findings without revealing secrets. Apply only approved, focused patches, run relevant tests, and verify the original finding ID is gone. Keep agent validation in `.reporook/agent-review.json` rather than rewriting deterministic findings.
