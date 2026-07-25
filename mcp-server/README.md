# RepoRook MCP server

Local, stdio-only security tools backed by the deterministic `reporook` CLI.

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

The server reads repository code and writes RepoRook evidence plus explicitly confirmed repository policy files. `get_policy_status` explains the deterministic team-policy result. `create_findings_baseline` and `suppress_finding` require `confirmed=true` after explicit approval; suppressions also require an owner, reason, and expiry. `prioritize_findings` queues only actionable findings and `prepare_remediation_plan` binds one finding to its source scan and exact proposal template. `record_remediation_approval` requires confirmation and hashes the exact plan, diff, files, and tests. Patch creation and application remain the host agent's responsibility. `verify_fix` reports `inconclusive` unless the original scanner completes under the same configuration; missing coverage never becomes a claimed fix.
