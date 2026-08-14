# Agent adapters

All host adapters consume the canonical `reporook-security` skill. Run `npm run sync:adapters` after editing it and `npm run validate:adapters` plus `npm run validate:agent-parity` before release. The machine-readable [`native-agent-parity.json`](../contracts/native-agent-parity.json) contract binds each host's package, MCP launch, validation/remediation surfaces, automatic gates, and repository-local install paths.

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

Parity means equivalent security properties, not identical host packaging. Every host receives the same canonical workflow assertions: never bootstrap missing software, never treat exit `2` as clean, never expose detected secrets, preserve deterministic-versus-agent provenance, prioritize only actionable policy findings, bind fixes to an exact proposal and human approval, and accept resolution only after same-scanner verification passes. The parity validator fails CI when any host loses one of those guarantees.

Cursor and Copilot package optional automatic stop hooks. Those hooks invoke only the already-installed `reporook` binary, preserve the repository or organization policy threshold, and use `--require-scanners` so missing applicable coverage is an error. They never install a scanner or replace repository configuration.

Codex Security, Claude Security, and Cursor Security Review are optional deep-validation layers. RepoRook does not redistribute, invoke without user intent, or relabel their findings.
