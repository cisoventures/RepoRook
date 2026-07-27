# Scanner isolation and sandbox expectations

RepoRook treats every scanned repository and every scanner result as untrusted. It bounds and isolates orchestration, but it is not a kernel sandbox: third-party scanner processes still run with the operating-system identity that launched RepoRook. For an unknown repository, use a disposable container or CI runner with the minimum filesystem, network, and credential access the selected scanners need.

## Common process controls

Every subprocess is launched directly with an argument array and `shell: false`. RepoRook never interpolates a repository value into a shell command. Scanner processes have a ten-minute default timeout and a 50 MiB combined stdout/stderr limit; Git and version probes use tighter bounds. Timeout, oversized output, malformed output, or a non-supported exit code becomes failed coverage rather than a clean scan.

| Process | Repository and local access | Network expectation | RepoRook controls | Residual consideration |
|---|---|---|---|---|
| Git | Reads revision and changed-file metadata | None expected | `--end-of-options`, validated commit IDs, 10 MiB output and 50,000-path limits | Repository Git hooks are not invoked by the read-only commands RepoRook uses |
| Semgrep | Reads the repository or selected changed files; cache/config/log files use a private temporary directory | The default `p/default` rules alias may download rules | Metrics and version checks disabled; explicit config; temporary XDG state | Use a pinned local rules file for offline and byte-reproducible scans |
| Gitleaks | Reads the working tree or, by explicit opt-in, Git history; writes a redacted temporary report | None expected | `--redact`; temporary report; 50 MiB report cap; malformed report fails coverage | History mode intentionally expands the repository data read |
| npm audit | Reads the root lockfile and npm configuration | Registry access is normally required | Direct `npm audit --json`; bounded output and runtime | Private-registry credentials available to npm remain available to this child process |
| pip-audit | Reads root Python requirements or lock data | Package-index and advisory access may be required | Explicit input and JSON output; bounded output and runtime | Index configuration and credentials available to pip tooling remain in scope |
| OSV-Scanner | Reads explicitly discovered complementary lockfiles | OSV/advisory access may be required | Explicit `--lockfile` arguments; bounded discovery, output, and runtime | Advisory freshness and availability remain external dependencies |
| Checkov | Reads selected infrastructure and workflow files; writes only a trusted temporary config | External policy, module, and result-upload access is disabled | Repository config ignored; uploads/downloads disabled; API and VCS tokens removed from the child environment | Built-in local policy coverage is scanner-owned and pre-1.0 |
| Trivy image | Reads only explicitly configured image references and may read registry credentials; cache is in a private temporary directory | Registry and vulnerability-database access are normally required | Trusted temporary config/cache, vulnerability scanner only, bounded image count/output/runtime | A private image scan intentionally grants Trivy the registry access available to the caller |

## Host boundaries

The MCP server accepts at most 1 MiB per JSON-RPC message. It caps one RepoRook CLI child at 50 MiB of output and 15 minutes, anchors evidence and source reads to the requested repository, and rejects links, non-files, invalid UTF-8, and oversized content. The local dashboard separately binds only to loopback, uses a private session, and applies its own request and artifact caps.

## Recommended execution profile

- Use an ephemeral, non-privileged runner for repositories you do not trust.
- Mount only the selected repository and a disposable temporary/cache directory.
- Do not expose cloud, package-registry, VCS, signing, or production credentials unless a selected scanner explicitly needs them.
- Prefer pinned scanner versions, pinned local Semgrep rules, immutable container digests, and read-only network egress to required registries and advisory services.
- Treat scanner installation and advisory/rule databases as supply-chain inputs; RepoRook's GitHub Action pins scanner versions and checksums downloaded binaries where a checksum artifact is available.

These expectations are part of the v0.9 hardening contract and should be reviewed again before v1.0 or whenever a scanner gains a new execution or network capability.
