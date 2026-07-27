# RepoRook MCP server

Local, stdio-only security tools backed by the deterministic `reporook` CLI, including source, dependency, infrastructure, workflow, explicit container-image, and opt-in Git-history coverage.

```json
{
  "mcpServers": {
    "reporook": {
      "command": "npx",
      "args": ["--yes", "@reporook/mcp-server"]
    }
  }
}
```

The server reads repository code and writes RepoRook evidence plus explicitly confirmed repository policy files. Container-image and historical findings expose provenance but deliberately return no pretend current-file context. `get_policy_status` explains the deterministic team-policy result. `create_findings_baseline` and `suppress_finding` require `confirmed=true` after explicit approval; suppressions also require an owner, reason, and expiry. `prioritize_findings` queues only actionable findings and `prepare_remediation_plan` binds one finding to its source scan and exact proposal template. `record_remediation_approval` requires confirmation and hashes the exact plan, diff, files, and tests. Patch creation and application remain the host agent's responsibility. `verify_fix` reports `inconclusive` unless the original scanner completes under the same configuration; missing coverage never becomes a claimed fix.

Tools that read an existing report require `repository_path`; relative and absolute `report_path` values must resolve inside that repository. Report and source-context reads reject symbolic links, non-files, invalid UTF-8, and oversized content rather than exposing unrelated local files or exhausting the host process. Stdio requests are capped at 1 MiB, and CLI child output and runtime are capped at 50 MiB and 15 minutes.
