# Roadmap

RepoRook develops in auditable vertical slices. Each milestone must keep deterministic scanner evidence separate from agent reasoning, fail closed when required coverage is missing, protect detected secrets, and preserve explicit approval before a security patch.

| Milestone | Status | Outcome |
|---|---|---|
| v0.1 Foundation | Complete | CLI, normalized findings, SARIF, GitHub Action, MCP, host adapters, plain-English explanations, verification receipts, and trusted publishing |
| v0.2 Detection breadth | Complete | Complementary OSV-Scanner coverage for nested and non-Node/Python dependency ecosystems without duplicate advisory noise |
| v0.3 Guided fixes | Implemented | Project initialization, deterministic fix queue, finding-bound remediation plans, exact patch/test preview requirements, agent-host workflow, and same-scanner verification |
| v0.4 Native agent experience | Planned | First-class installation and consistent conversational commands for Claude Code, Codex, Cursor, Copilot, Gemini, and Windsurf |
| v0.5 Team policy | Planned | New-findings baselines, expiring suppressions with owners and reasons, path-specific policy, and durable approval evidence |
| v0.6 Infrastructure coverage | Planned | Terraform, Kubernetes, Docker, GitHub Actions, container, and optional Git-history secret checks through fixture-backed adapters |
| v0.7 No-code service | Planned | Optional GitHub App, onboarding wizard, repository dashboard, approval queue, remediation pull requests, and a self-hosted deployment path |
| v0.8 Scale and reliability | Planned | Incremental scans, caching, large-monorepo performance, retry/resume behavior, and organization policy management |
| v0.9 Hardening | Planned | Threat model, parser fuzzing, hostile-repository testing, sandbox review, external audit, and security response readiness |
| v1.0 Stable platform | Planned | Stable CLI, MCP, and schema contracts with compatibility guarantees, migrations, governance, and long-term release policy |

Priorities may change when fixture evidence, user research, or a security boundary requires it. Scanner count alone is not a progress metric; each new integration must improve trustworthy coverage without creating misleading success or unusable noise.
