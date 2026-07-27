# External security review package

This document gives an independent reviewer a reproducible scope for RepoRook. [`SECURITY.md`](../SECURITY.md) remains the authoritative threat model and vulnerability-reporting policy; this package translates it into review work and expected evidence.

## Review objective

Determine whether a hostile repository, scanner, MCP client, browser client, dependency service, or release input can cause RepoRook to:

- execute repository-controlled commands outside an explicitly invoked scanner;
- read or write outside the selected repository or approved local configuration;
- preserve, print, or transmit a detected secret value;
- forge deterministic evidence, approval, or verification state;
- report complete or clean coverage after a required operation failed;
- use GitHub credentials for a repository other than the one selected and approved;
- consume unbounded CPU, memory, output, filesystem traversal, or request input.

## In scope

- `cli/`: configuration, repository traversal, scanner planning/execution, parser normalization, caching, policy, artifacts, remediation, approval, and verification.
- `mcp-server/`: JSON-RPC framing, tool schemas, repository/source reads, CLI process control, and write authorization.
- `service/`: loopback session, request and artifact limits, App-manifest onboarding, installation verification, credential storage, exact-patch materialization, and draft-PR publication.
- `action/` and `.github/workflows/`: token permissions, scanner installation, checksums, SARIF/comment/artifact publication, and release provenance.
- `adapters/`: whether host instructions preserve the deterministic-evidence and exact-approval boundaries.
- npm package contents, schemas, fixtures, release metadata, and compatibility among the three published packages.

Third-party scanner detection accuracy is not itself a RepoRook defect unless RepoRook misstates coverage, corrupts evidence, leaks protected data, or invokes the scanner unsafely.

## Priority attack scenarios

1. A repository uses links, unusual names, deep trees, huge files, malicious Git metadata, or configuration keys to escape a path boundary or exhaust the process.
2. A scanner emits malformed, mixed-stream, secret-bearing, enormous, partial, or contradictory output and RepoRook treats it as a clean completed scan.
3. A forged findings artifact makes an MCP tool read an unrelated local file or makes approval/verification bind to different content.
4. A browser request bypasses the loopback session, Host/Origin checks, proposal digest, approval receipt, source commit, or separate publish confirmation.
5. A spoofed GitHub App callback, installation ID, repository response, default-branch race, or patch path broadens access or changes the approved diff.
6. A compromised release input publishes unexpected package files, bypasses checks, or uses a credential where OIDC trusted publishing is expected.

## Reviewer starting evidence

- [`SECURITY.md`](../SECURITY.md) — authoritative assets, boundaries, invariants, and reportable findings.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — execution, policy, service, and publishing flows.
- [`HARDENING.md`](HARDENING.md) — hostile-input and fuzzing contract.
- [`SANDBOXING.md`](SANDBOXING.md) — per-process access and residual risk.
- [`SERVICE.md`](SERVICE.md), [`TEAM_POLICY.md`](TEAM_POLICY.md), and [`GUIDED_FIX.md`](GUIDED_FIX.md) — user-visible security contracts.
- `schemas/` and `test-fixtures/` — deterministic evidence contracts and adversarial fixtures.

Reproduce the maintained baseline with:

```bash
npm ci
npm run check
npm run smoke:packages
npm run fixture:prepare
npm run fixture:guided
npm run fixture:policy
```

GitHub Actions is the source of truth for loopback HTTP tests that cannot bind in a restricted local sandbox, plus CodeQL and the end-to-end RepoRook example workflow.

## Requested review methods

- Manual source review of every filesystem, process, credential, and approval boundary.
- Property or coverage-guided fuzzing beyond the committed seeded corpus, with minimized regression inputs contributed when safe.
- Linux, macOS, and Windows hostile-filesystem tests, including junction/reparse behavior on Windows.
- Fault injection for truncated files, process termination, partial scanner output, GitHub API errors, and branch movement.
- Package-tarball and workflow permission review from a clean clone.
- Validation that error messages, terminal output, SARIF, comments, MCP responses, and service responses cannot retain secret-shaped scanner fields.

## Known residual questions

- Third-party scanners are bounded child processes, not kernel-sandboxed; disposable least-privileged runners are still recommended.
- Network egress is scanner-specific and not centrally allowlisted.
- Private registry/index scans may intentionally expose the corresponding package or image credentials to that scanner child.
- Native coverage-guided fuzzing and independent Windows link/junction review remain valuable beyond the deterministic cross-platform corpus.
- Scanner rules and advisory databases remain external supply-chain inputs even when the scanner binary itself is pinned.

## Deliverable format

For each issue, provide the affected revision and package, preconditions, exact boundary crossed, impact, a safe minimal reproducer, and whether coverage or secret-handling claims become incorrect. Do not include live credentials or third-party private source. Report privately using the process in [`SECURITY.md`](../SECURITY.md).
