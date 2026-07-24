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

The server reads repository code and writes only RepoRook evidence under `.reporook/`. `prioritize_findings` creates a deterministic fix queue and `prepare_remediation_plan` binds one finding to its source scan, exact-preview requirements, approval boundary, and verification command. Patch creation and application remain the host agent's responsibility and require user approval. `verify_fix` reports `inconclusive` unless the original scanner completes under the same configuration; missing coverage never becomes a claimed fix.
