# RepoRook MCP server

Local, stdio-only security tools backed by the deterministic `reporook` CLI, including source, dependency, infrastructure, workflow, explicit container-image, and opt-in Git-history coverage.

```json
{
  "mcpServers": {
    "reporook": {
      "command": "reporook-mcp",
      "args": []
    }
  }
}
```

Install `@reporook/mcp-server` yourself before adding this entry. Generated configuration never invokes `npx`, downloads packages, or installs software; a missing `reporook-mcp` binary fails visibly.

The server reads repository code and writes RepoRook evidence plus explicitly confirmed repository policy files. Container-image, historical, and Gitleaks findings deliberately return no current-file context. `get_policy_status` explains the team-policy result. `create_findings_baseline` and `suppress_finding` require `confirmed=true` after explicit approval; suppressions also require an owner, reason, and expiry. `prioritize_findings` queues only actionable findings and `prepare_remediation_plan` binds one finding to its source scan and exact proposal template. Approval receipts are intentionally unavailable over MCP because a client cannot independently prove a human approved its request; the user records an exact approval through the trusted CLI boundary. Patch creation and application remain the host agent's responsibility. `verify_fix` reports `inconclusive` unless the original scanner completes under the same configuration; missing coverage never becomes a claimed fix.

Tools that read an existing report require `repository_path`; relative and absolute `report_path` values must resolve inside that repository. Reports must pass the complete runtime schema and cross-field consistency checks and are labeled as unverified repository artifacts unless produced by a fresh operation. Report and source-context reads reject symbolic links, path swaps, non-files, invalid UTF-8, and oversized content rather than exposing unrelated local files or exhausting the host process. Stdio requests are capped at 1 MiB, at most two tool calls may run concurrently, and CLI child output and runtime are capped at 50 MiB and 15 minutes.
