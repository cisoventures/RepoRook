# RepoRook security policy and threat model

## Supported versions

Security fixes are applied to the latest released minor version. This project is pre-1.0; pin releases in CI and review changelogs before upgrading.

## Reporting a vulnerability

Do not open a public issue for a vulnerability in RepoRook. Use GitHub private vulnerability reporting for the repository. Include affected versions, reproduction steps, impact, and a safe proof of concept. Never include live credentials or third-party private code.

The project is community-maintained with no SLA. Maintainers will coordinate validation and disclosure as capacity allows.

## Assets

- Source code and secrets in repositories scanned by users
- Integrity of normalized findings, SARIF, and scan receipts
- The local developer environment and CI runner
- User trust in coverage and remediation status

## Trust boundaries

- RepoRook invokes third-party scanner executables as subprocesses.
- Scanner output is untrusted input and must be parsed without executing content.
- MCP clients and host agents are outside the deterministic core.
- GitHub comments, SARIF, and artifacts cross from the runner to GitHub APIs.
- npm, Python, scanner rules, and vulnerability databases are external supply-chain inputs.

## Security invariants

- Never preserve or print raw detected secret values.
- Never call partial or failed coverage clean.
- Never let host-agent opinions silently alter deterministic findings.
- Never apply application patches from the CLI or MCP server.
- Keep finding and artifact paths inside the selected repository.
- Use argument arrays rather than shell interpolation for scanner execution.
- Pin and checksum downloaded CI scanner binaries.

## Reportable findings

Credential disclosure, arbitrary command execution, repository path traversal, finding forgery, unsafe artifact permissions, CI token exposure, or a bypass that reports complete coverage when required scanners did not run are security issues.

## Exclusions

RepoRook does not scan the supply chain of installed agents, skills, plugins, or MCP servers. Scanner false negatives caused by unsupported languages or third-party rule coverage should be documented as coverage limitations rather than vulnerabilities in RepoRook, unless RepoRook incorrectly reports complete coverage.
