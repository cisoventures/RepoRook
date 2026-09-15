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
| v0.9 Hardening | Implemented | Authoritative repository threat model; hostile configuration and path boundaries; deterministic parser fuzzing; bounded hostile inputs; sandbox guidance; external-review package; and security response readiness |
| v1.0-rc.1 Audit and beginner hardening | Merged; final gates pending | PR #48 merged the reviewed remediation; V1-STALE and the two manual environment exercises remain before publication |
| v1.0 Stable platform | Blocked on three release gates | Stable CLI, MCP, service, schema, Action, and native-agent contracts with compatibility guarantees, migrations, governance, and long-term release policy |
| Post-1.0 team service | Research | Authenticated TLS deployment, repository-scoped multi-user GitHub App, RBAC, queues, audit logs, shared policy, encrypted credentials, and self-hosting guidance |

The beginner path has an executable [acceptance harness](ACCEPTANCE.md) covering fail-closed partial coverage, non-installing recovery guidance, plain-English evidence, current-commit enforcement, exact proposal approval, repository-scoped remote patch materialization, and draft-only publication while the local working tree remains unchanged. The stable v1 surface has a machine-readable [`contracts/v1.json`](../contracts/v1.json) snapshot, an executable CI compatibility gate, and a documented [compatibility and migration policy](COMPATIBILITY.md). Native-agent parity has a separate stable six-host [contract](../contracts/native-agent-parity.json) and executable gate. An independent review produced a complete finding set; the [remediation ledger](SECURITY_REMEDIATION.md) maps every ID to its control and regression evidence. V1-STALE re-verification and the two manual environment exercises remain the external release gates.

## v1.0 release gates

1. **Independent security review.** PR #48 is merged. The reviewer must verify the V1-STALE follow-up before publication.
2. **Real Windows validation.** Release-blocking RR-FS-01 exercise is scheduled and assigned in [#53](https://github.com/cisoventures/RepoRook/issues/53); hosted CI does not close it.
3. **Real browser validation.** Release-blocking RR-SVC-01 exercise is scheduled and assigned in [#54](https://github.com/cisoventures/RepoRook/issues/54); Node HTTP tests do not close it.
4. **Beginner-grade local journey.** A user can connect a repository, understand which checks ran, obtain safe setup guidance, scan, understand the first risk, review an exact patch and test plan, approve it, verify it, and open a draft pull request without mistaking partial coverage for safety.
5. **Safe automated resolution.** Agent-generated changes remain finding-bound, proposal-hash-bound, explicitly approved, isolated from the local working tree, tested, rescanned, and published only as a draft pull request.
6. **Stable public contracts.** Implemented: documented CLI flags and exit codes, MCP tools, configuration and evidence schemas, package entry points, migration behavior, deprecation policy, and the compatibility test matrix are frozen and checked in CI.
7. **Native-agent parity.** Implemented: Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, and Windsurf are checked against the same evidence, coverage, secret-redaction, approval, and verification boundaries while retaining host-native packaging.

The hosted multi-user service is intentionally outside the v1.0 release boundary. The loopback, one-user, one-repository service should survive independent review before authentication, tenancy, durable queues, or broader credential handling are introduced.

Priorities may change when fixture evidence, user research, or a security boundary requires it. Scanner count alone is not a progress metric; each new integration must improve trustworthy coverage without creating misleading success or unusable noise.
