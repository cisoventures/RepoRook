# Agent adapters

All host adapters consume the canonical `reporook-security` skill. Run `npm run sync:adapters` after editing it and `npm run validate:adapters` before release.

| Host | Package |
|---|---|
| Claude Code | `adapters/claude/reporook` |
| Codex | `adapters/codex/reporook` |
| Cursor | `adapters/cursor/reporook` |
| GitHub Copilot CLI | `adapters/copilot/reporook` |
| Gemini CLI | `adapters/gemini/reporook` |

Each package points to the local stdio MCP server. Claude, Cursor, Copilot, and Gemini also include native reviewer definitions. Reviewer agents are read-only; fixer agents are separately invoked and must honor approval.

Codex Security, Claude Security, and Cursor Security Review are optional deep-validation layers. RepoRook does not redistribute, invoke without user intent, or relabel their findings.
