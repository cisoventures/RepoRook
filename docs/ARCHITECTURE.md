# Architecture

RepoRook has one deterministic execution path:

```text
host plugin → stdio MCP → RepoRook CLI → scanner subprocesses
                         ├────────────→ team policy + priorities
                         └────────────→ remediation plans + approval receipts
GitHub Action ───────────┘
Local dashboard ─────────┘
       └─ exact approval + selected-repository App token → draft pull request
```

## Core boundary

The CLI detects applicable scanners, invokes them without a shell, parses untrusted JSON, removes secret material, normalizes findings, deduplicates stable fingerprints, calculates coverage, and writes JSON/SARIF/receipt artifacts. Semgrep metrics are disabled. Its default public rule alias can be replaced with a pinned local rules file through `semgrepConfig`; that local-file mode is the reproducible and offline option.

Repository configuration is untrusted input. RepoRook accepts only a regular, non-symbolic-link configuration file inside the selected repository, caps it at 1 MiB before and after reading, rejects prototype-sensitive mapping keys, and treats a missing explicit `--config` as an error. The small YAML subset is parsed without evaluation or custom types. Organization policy has the same repository and symlink boundary with a tighter 256 KiB cap.

Previously written evidence is also untrusted when it is read back. CLI findings, team-policy, remediation, approval, and cache inputs must remain regular non-link files, contain valid UTF-8 JSON, and fit within a 10 MiB read limit. Gitleaks is the exception because its scanner-owned report may be larger: that file is capped at 50 MiB, and missing, malformed, or structurally unexpected output becomes scanner failure. MCP tools anchor every report path to an explicit repository, reject symbolic-link path components, and cap source context at 1 MiB so a forged finding cannot turn a read-only tool into an arbitrary local-file reader. The stdio boundary accepts at most 1 MiB per JSON-RPC message; a RepoRook CLI child may emit at most 50 MiB and run for at most 15 minutes before the MCP call fails closed.

Dependency ownership is explicit. Root `package-lock.json` belongs to `npm audit`; root requirements files, `poetry.lock`, and `uv.lock` belong to `pip-audit`. OSV-Scanner receives other supported manifests and supported nested-project files. This expands ecosystem and monorepo coverage without duplicate results from overlapping scanners. Generated dependency and build directories are not traversed during OSV applicability discovery.

Changed-file execution is an explicit planning phase, not a post-scan filter. Each adapter reports one of four scopes in the receipt: `repository`, `changed-files`, `external-targets`, or `not-applicable`. Semgrep, dependency, and infrastructure adapters receive only owned, applicable changed files; exact configured files and nested workspace manifests remain in scope. Gitleaks intentionally remains repository-wide to preserve safe secret detection, while Trivy remains limited to explicitly configured external images. Invalid, missing, ignored, outside-repository, and symbolic-link changed paths are never passed to scanners. No relevant adapter work becomes an auditable non-applicable result rather than an implicit successful scan.

Checkov receives only local Terraform, Kubernetes, Helm, Kustomize, Dockerfile, and GitHub Actions frameworks. RepoRook supplies an empty trusted config, disables result uploads, cloud policy downloads, external module downloads, and inherited API tokens, and ignores repository-supplied Checkov settings. Checkov's offline local policies do not consistently carry severity, so missing severities normalize to `medium` rather than being overstated.

Trivy image scanning is a separate external-target adapter. It receives at most 20 validated image references from `containerImages`; RepoRook never guesses an image, builds one, or broadens the target from a Dockerfile. Tags are supported, but digests provide reproducible identity. Gitleaks scans the working tree by default and switches to redacted Git-history mode only when `gitHistory` is true. Historical and image findings retain safe provenance, bypass changed-file/path filtering that only makes sense for current repository files, and do not create misleading SARIF or MCP source locations.

Successful scanners form independent resumable checkpoints under `.reporook/cache/v1`. Reuse requires a Git commit, no relevant working-tree changes, the same RepoRook and scanner versions, the complete normalized configuration, the same changed-file scope, an unexpired record, and a valid HMAC from a host-local key stored outside the repository. The default 15-minute lifetime bounds staleness from advisory databases, public rules, and mutable image tags. Cache files are size-bounded, mode `0600`, atomically replaced beneath mode-`0700` directories, never followed through symbolic links, authenticated before reconstruction, and strictly reconstructed as untrusted JSON. A forged, malformed, or stale record is a miss. Scanner errors and unavailable results are never written. Error results are retried a bounded number of times and each successful scanner is checkpointed immediately, so an interrupted multi-scanner run can resume completed work without turning missing coverage into success. Verification bypasses all cache reads. Scanner subprocess output is capped at 50 MiB, Git diff/status output at 10 MiB, and changed-file lists at 50,000 entries so hostile or unusually large repositories fail closed instead of exhausting memory.

The MCP server shells out to the CLI and exposes scan, team-policy, priority, remediation-plan, approval-receipt, evidence, and verification tools. Its local writes are limited to RepoRook evidence and explicitly confirmed repository policy files; it does not apply patches. The Action builds and invokes the same CLI. Neither owns scanner parsing.

Repository-local agent integration management applies the same hostile-filesystem model. Destination paths remain inside the repository and cannot contain symbolic links; host configuration is valid UTF-8 capped at 2 MiB, the ownership receipt is capped at 1 MiB and reconstructed against the fixed adapter allowlist, and one conflict blocks the entire write pass.

The optional local dashboard is another thin CLI client. It binds only to a literal loopback address, establishes a private session from a random URL-fragment token, validates Host and Origin on state-changing requests, caps request and artifact sizes, rejects symbolic-link artifact paths, and returns a deliberately reduced finding view. It can initialize RepoRook, start scans, prepare plans, and record approval receipts without editing local application files. For GitHub publishing, it detects the `github.com` origin and uses GitHub's App-manifest flow to create a private App with metadata-read, contents-write, and pull-request-write repository permissions. The random, expiring manifest state is kept in memory. The setup callback's untrusted `installation_id` is checked with an App JWT against the exact repository before credentials are stored. App keys live outside the repository in a mode-`0600` local config file; one-hour installation tokens are minted with an explicit single-repository and reduced-permission request. The publisher then verifies installation visibility again, requires the remote default branch to equal the approved scan commit, materializes the exact text patch in a disposable directory, and creates a draft pull request. Remote multi-user dashboard access remains outside the loopback service boundary.

## Coverage

`complete` means every applicable, enabled scanner finished successfully. `partial` means at least one completed and at least one applicable scanner was unavailable or failed. `failed` means no applicable scanner completed. Non-applicable scanners remain visible but do not reduce coverage.

Incomplete coverage exits with tool error code `2` by default in the CLI, MCP-backed scans, and Action. The only override is the explicit `--allow-no-coverage` diagnostic flag. Configuration validation rejects unknown scanners and required/disabled contradictions before execution.

## Identity

Source findings hash scanner, rule, repository-relative file, and stable matched evidence. Dependency findings hash scanner, package, and advisory. Line numbers are excluded so ordinary code movement does not churn IDs.

## Team policy

Policy evaluation is a deterministic layer beside findings, never a mutation of scanner evidence. A committed baseline matches stable fingerprints and distinguishes existing from new findings. Suppressions bind one finding ID to an owner, reason, creation time, and expiry; malformed policy exits with tool error and expired suppressions are evaluated normally. Path-specific thresholds can only tighten the global gate. An optional committed organization profile establishes a minimum global threshold, required scanners, and path thresholds. Local configuration may tighten but cannot weaken that profile. The profile is bounded, repository-relative, non-symbolic-link input; its identity and raw content hash are included in policy evidence and the effective configuration hash so verification detects any change.

## Remediation

Prioritization is deterministic, severity-led, and limited to policy-actionable findings. A remediation plan binds one stable finding to the source commit and configuration, requires an exact unified diff and test plan, and keeps approval pending. A named approver's receipt hashes the plan, proposal, patch, file list, and tests; changing any bound value invalidates it. Host agents may validate, explain, and patch only outside the deterministic finding artifact. They apply a change only after approval of that exact proposal and stop when scope changes. `verify_fix` validates an available approval receipt, then checks whether the original scanner completed under the same configuration before checking the stable finding and equivalent rule/file matches. Missing scanner evidence or changed configuration produces `inconclusive`, never `passed`. Repository tests and human review establish functional confidence.
