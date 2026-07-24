# Agent adapters

All host adapters consume the canonical `reporook-security` skill. Run `npm run sync:adapters` after editing it and `npm run validate:adapters` before release.

The CLI packages these adapters and installs only repository-local integration files:

```bash
reporook integrate install . --apply
reporook integrate doctor .
reporook integrate update . --apply
reporook integrate uninstall . --apply
```

Without `--apply`, mutating commands are previews. The lifecycle receipt stores content hashes in `.reporook/integrations.json`; update and uninstall refuse user-modified destinations. JSON integrations are merged at the owned entry, preserving unrelated configuration. See [`AGENT_SETUP.md`](AGENT_SETUP.md) for the concrete host paths and trust prompts.

| Host | Package |
|---|---|
| Claude Code | `adapters/claude/reporook` |
| Codex | `adapters/codex/reporook` |
| Cursor | `adapters/cursor/reporook` |
| GitHub Copilot CLI | `adapters/copilot/reporook` |
| Gemini CLI | `adapters/gemini/reporook` |
| Windsurf | `adapters/windsurf/reporook` |

Each package points to the local stdio MCP server. Reviewers confirm coverage and use the deterministic priority queue. Fixers prepare a finding-bound remediation plan, display the exact diff and test plan, require approval for that proposal, stop when scope changes, and report functional tests separately from RepoRook scanner resolution. Codex and Windsurf enforce the same lifecycle through their native skill and workflow formats.

Codex Security, Claude Security, and Cursor Security Review are optional deep-validation layers. RepoRook does not redistribute, invoke without user intent, or relabel their findings.
