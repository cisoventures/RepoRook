# Changelog

All notable changes to RepoRook are documented here. RepoRook follows semantic versioning while its public contracts remain pre-1.0.

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
