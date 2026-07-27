# Roadmap

RepoRook develops in auditable vertical slices. Each milestone must keep deterministic scanner evidence separate from agent reasoning, fail closed when required coverage is missing, protect detected secrets, and preserve explicit approval before a security patch.

| Milestone | Status | Outcome |
|---|---|---|
| v0.1 Foundation | Complete | CLI, normalized findings, SARIF, GitHub Action, MCP, host adapters, plain-English explanations, verification receipts, and trusted publishing |
| v0.2 Detection breadth | Complete | Complementary OSV-Scanner coverage for nested and non-Node/Python dependency ecosystems without duplicate advisory noise |
| v0.3 Guided fixes | Complete | Project initialization, deterministic fix queue, finding-bound remediation plans, exact patch/test preview requirements, agent-host workflow, and same-scanner verification |
| v0.4 Native agent experience | Implemented | First-class repository-local install, update, doctor, and safe uninstall plus consistent conversational workflows for Claude Code, Codex, Cursor, Copilot, Gemini, and Windsurf |
| v0.5 Team policy | Implemented | New-findings baselines, expiring suppressions with owners and reasons, path-specific policy, and durable approval evidence |
| v0.6 Infrastructure coverage | Implemented | Terraform, Kubernetes, Docker, GitHub Actions, explicit container-image, and optional redacted Git-history secret checks through fixture-backed adapters |
| v0.7 No-code service | Implemented | Local onboarding, dashboard, scan control, exact-proposal approval, guided private GitHub App installation, one-repository short-lived credentials, and approval-bound draft PR publishing |
| v0.8 Scale and reliability | Implemented | Commit-, version-, configuration-, and scope-bound scanner checkpoints; bounded freshness; safe retry/resume; workspace-aware incremental scans; bounded subprocess and Git output; and hash-bound organization policy profiles |
| v0.9 Hardening | Implemented | Authoritative repository threat model; hostile configuration and path boundaries; deterministic parser fuzzing; bounded hostile inputs; sandbox guidance; external-review package; and security response readiness. Independent external audit remains follow-up work. |
| v1.0 Stable platform | Planned | Stable CLI, MCP, and schema contracts with compatibility guarantees, migrations, governance, and long-term release policy |

Priorities may change when fixture evidence, user research, or a security boundary requires it. Scanner count alone is not a progress metric; each new integration must improve trustworthy coverage without creating misleading success or unusable noise.
