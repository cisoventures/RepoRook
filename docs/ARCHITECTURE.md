# Architecture

RepoRook has one deterministic execution path:

```text
host plugin → stdio MCP → RepoRook CLI → scanner subprocesses
GitHub Action ────────────────────────→ RepoRook CLI
```

## Core boundary

The CLI detects applicable scanners, invokes them without a shell, parses untrusted JSON, removes secret material, normalizes findings, deduplicates stable fingerprints, calculates coverage, and writes JSON/SARIF/receipt artifacts. Semgrep metrics are disabled. Its default public rule alias can be replaced with a pinned local rules file through `semgrepConfig`; that local-file mode is the reproducible and offline option.

The MCP server shells out to the CLI and exposes read-only evidence and verification tools. The Action builds and invokes the same CLI. Neither owns scanner parsing or severity policy.

## Coverage

`complete` means every applicable, enabled scanner finished successfully. `partial` means at least one completed and at least one applicable scanner was unavailable or failed. `failed` means no applicable scanner completed. Non-applicable scanners remain visible but do not reduce coverage.

Failed coverage exits with tool error code `2` by default in the CLI, MCP-backed scans, and Action. The only override is the explicit `--allow-no-coverage` diagnostic flag. Configuration validation rejects unknown scanners and required/disabled contradictions before execution.

## Identity

Source findings hash scanner, rule, repository-relative file, and stable matched evidence. Dependency findings hash scanner, package, and advisory. Line numbers are excluded so ordinary code movement does not churn IDs.

## Remediation

Host agents may validate, explain, and patch only outside the deterministic finding artifact. `verify_fix` checks whether the original scanner completed under the same configuration before checking the stable finding and equivalent rule/file matches. Missing scanner evidence or changed configuration produces `inconclusive`, never `passed`. Repository tests and human review establish functional confidence.
