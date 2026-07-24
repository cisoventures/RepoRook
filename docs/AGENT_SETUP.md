# Agent setup

RepoRook can install repository-local integrations for Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, and Windsurf. It does not need an API key, and it does not change personal or system-wide agent settings.

## Install in one command

From the root of the repository you want to protect:

```bash
npx --yes reporook@latest integrate install . --apply
```

The default is `--host all`, so the same repository works for teammates using different coding agents. To configure only selected hosts:

```bash
npx --yes reporook@latest integrate install . --host claude,cursor --apply
```

Remove `--apply` to preview every file and JSON entry first. RepoRook blocks the entire write pass if a destination contains content it does not own.

Restart the coding agent after installation. The host may ask you to trust the repository, its MCP server, or its local plugin. Review and accept that prompt only if this is the repository you intended to configure.

## What to ask

Use ordinary language. The same workflow is installed for every host:

- “Scan this project for security vulnerabilities and explain the results simply.”
- “What should I fix first, and why?”
- “Explain finding `rr-…` like I do not know security jargon.”
- “Prepare a safe fix for finding `rr-…`, but do not change code yet.”
- “Show me the exact change and tests before I approve it.”
- “Apply the change I approved and verify that the original finding is gone.”

RepoRook keeps scanner evidence separate from the agent's judgment. It will not treat incomplete coverage as clean, expose detected secret values, or let an agent silently broaden an approved patch.

## Check, update, or remove

```bash
npx --yes reporook@latest integrate doctor .
npx --yes reporook@latest integrate update . --apply
npx --yes reporook@latest integrate uninstall . --apply
```

Use `--host cursor` or another comma-separated host list to limit any command. `doctor` is always read-only. Install, update, and uninstall show a preview unless `--apply` is present.

RepoRook records hashes in `.reporook/integrations.json`. Update replaces only content whose hash still matches the receipt. Uninstall removes only unchanged RepoRook-managed content. If a person or another tool edited one of those files, RepoRook stops and names the conflict instead of overwriting or deleting it.

## Host behavior

| Host | Repository-local integration |
|---|---|
| Claude Code | Skill, reviewer/fixer agents, and `.mcp.json` server entry |
| Codex | Repo marketplace entry and plugin containing the skill and MCP server |
| Cursor | Skill, reviewer/fixer agents, project rule, and `.cursor/mcp.json` entry |
| GitHub Copilot | Skill, reviewer/fixer agents, and `.github/mcp.json` entry |
| Gemini CLI | Skill, reviewer/fixer agents, and `.gemini/settings.json` MCP entry |
| Windsurf | Skill, rule, and `/reporook-security` workflow |

Windsurf currently documents MCP configuration at user scope rather than repository scope. RepoRook deliberately leaves that global file untouched. The installed Windsurf skill and workflow use the RepoRook CLI directly, so scanning, explanation, planning, and verification still work without MCP.

