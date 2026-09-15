# Changelog

All notable changes to RepoRook are documented here. RepoRook follows semantic versioning and the stable v1 compatibility policy.

## Unreleased

## 1.0.0 - 2026-08-15

### Security

- Authenticate findings, cache evidence, and approval receipts with a protected host-local, repository-bound HMAC; strictly reconstruct evidence and reject unsigned, copied, malformed, inconsistent, oversized, linked, or race-swapped artifacts.
- Bind suppressions to exact finding fingerprints and require a trusted per-invocation opt-in before repository suppressions can affect policy.
- Move Semgrep rule authority to the trusted invocation boundary, bind local rules by digest, and require explicit network authorization for non-default remote rules.
- Fail closed on npm-audit operational errors, preserve distinct Gitleaks occurrences, cap pip-audit and OSV-Scanner repository fanout, sanitize executable search paths, and harden option and path boundaries across CLI and MCP.
- Bound and label scanner-controlled agent text, correct report finding counts, serialize repository scans, redact MCP errors, and make Action outputs fresh, exact, and resistant to stale files or workflow-command injection.
- Require complete proposal display and exact digest approval, bind approver attribution cryptographically, reject stale source state, and accept remote publication only when GitHub confirms a draft pull request.
- Replace loopback cookies with rotating exact-origin bearer sessions, consume GitHub App onboarding state on every outcome, and strengthen no-follow artifact reads.
- Split validation from the privileged release job, remove checkout and repository execution from the OIDC job, require the exact current `main` commit, minimize credentials, and document safe partial-stage recovery.

### Added

- Add adversarial regression coverage for forged evidence and approvals, option injection, traversal, stale Action outputs, output delimiters, operational scanner errors, oversized proposals, concurrent scans, draft-only publishing, loopback session boundaries, and release-workflow privilege separation.
- Add explicit suppression controls across CLI, MCP, service, and GitHub Action plus operator-selected Semgrep rule inputs and optional SARIF/comment permissions.

### Changed

- Promote the machine-readable CLI, MCP, service, schema, Action, and six-host agent-parity contracts to stable v1.
- Pin every published GitHub Action example to immutable commit SHAs.
- Update the CLI, MCP server, local service, and native adapter package versions together to `1.0.0`.

The accepted findings from the independent external review are remediated in this source. Publication remains gated on an independent regression re-review and the protected CI/release checks.

## 0.9.3 - 2026-08-14

### Security

- Require trusted per-invocation authorization before scanning repository-configured container images, strip generic Trivy registry credentials from version probes and scans, preserve host-scoped Docker authentication, and record the exact approved targets in scan receipts.

### Added

- Add a machine-readable external-review contract and one-command offline baseline that records revision, platform, command results, and integrity hashes without installing scanners or external software or asserting an audit opinion.
- Add a machine-readable v1 release-candidate contract and CI gate for package entry points, CLI behavior, MCP tools, configuration, evidence schemas, GitHub Action inputs and outputs, and the supported platform matrix.
- Document the post-v1 compatibility, deprecation, and migration policy.
- Add a six-host native-agent parity contract and executable validation gate for evidence, coverage, secret-redaction, approval, verification, MCP, and repository-local lifecycle guarantees.

### Changed

- Update every CodeQL action component atomically and group future Dependabot updates so mixed releases cannot break analysis.
- Reject linked Action artifact source directories and exercise CLI, MCP, service, integration, and Action directory-link boundaries with real Windows junctions in CI.
- Document CLI help aliases and stable exit-code meanings directly in `reporook --help`.
- Remove a stale README reference to an MCP approval tool; remediation approval intentionally remains at the trusted CLI or local-service boundary.
- Make Cursor and Copilot automatic hooks honor repository policy thresholds and fail closed when applicable scanner coverage is unavailable.
- Add the default-false external-target authorization control to CLI scan/verify, MCP scan/verify tools, the local service, and the GitHub Action. Existing `containerImages` users must explicitly opt in at the trusted invocation boundary.

## 0.9.2 - 2026-07-28

### Security

- Fail closed when applicable scanners do not complete unless the caller explicitly opts into diagnostic partial coverage.
- Bind verification to the original finding evidence so moved Semgrep findings or cosmetic evidence drift cannot be mistaken for successful remediation.

### Changed

- Make clean CI, GitHub Action tests, package typechecking, and RepoRook's self-scan path deterministic across supported platforms.
- Preserve the no-download security posture for the self-scan by requiring only the already available Gitleaks scanner.

## 0.9.1 - 2026-07-27

### Changed

- Complete the 0.9 release across the CLI, MCP server, and local service after the initial 0.9.0 npm publication only completed for the CLI and MCP packages.
- GitHub Action examples now pin the v0.9.1 release.

No product behavior changed from 0.9.0. The v0.9.1 release supersedes the incomplete 0.9.0 package set.

## 0.9.0 - 2026-07-27

### Added

- Deterministic fuzz coverage for the seven scanner normalizers plus policy and approval parsers.
- Explicit sandbox guidance, a reproducible external security-review package, and a security response runbook.
- Bounded evidence, scanner-report, MCP, and integration inputs to limit hostile-repository resource consumption.

### Security

- Confine configuration, report, and source paths to the selected repository and reject prototype-like configuration keys.
- Fail closed when Gitleaks emits malformed output instead of treating the scan as clean.
- Use a private temporary Trivy cache rather than a repository-controlled cache path.

### Changed

- `get_policy_status` and `list_findings` now require `repository_path` so MCP reads have an explicit repository boundary.
- GitHub Action examples now pin the v0.9.0 release.

Independent external audit remains planned; this release includes the review package needed to perform one.
