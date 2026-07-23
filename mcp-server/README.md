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

The server reads repository code and writes only RepoRook evidence under `.reporook/`. Patch creation and application remain the host agent's responsibility and require user approval. `verify_fix` reports `inconclusive` unless the original scanner completes under the same configuration; a disappeared finding caused by missing coverage is never called fixed.
