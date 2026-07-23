# Agent adapters

All host adapters consume the canonical `reporook-security` skill. Run `npm run sync:adapters` after editing it and `npm run validate:adapters` before release.

| Host | Package |
|---|---|
| Claude Code | `adapters/claude/reporook` |
| Codex | `adapters/codex/reporook` |
| Cursor | `adapters/cursor/reporook` |
| GitHub Copilot CLI | `adapters/copilot/reporook` |
| Gemini CLI | `adapters/gemini/reporook` |
| Windsurf | `adapters/windsurf/reporook` |

Each package points to the local stdio MCP server. Claude, Cursor, Copilot, and Gemini include read-only reviewer definitions plus separately invoked fixer definitions. Fixers require approval for one exact proposal, stop when scope changes, and report functional tests separately from RepoRook scanner resolution. Codex and Windsurf enforce the same lifecycle through their native skill and workflow formats.

Codex Security, Claude Security, and Cursor Security Review are optional deep-validation layers. RepoRook does not redistribute, invoke without user intent, or relabel their findings.
