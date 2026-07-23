# Contributing to RepoRook

RepoRook is community-maintained with no service-level agreement. Use GitHub Discussions for design questions and issues for reproducible defects.

## Development

1. Use Node.js 20 or later.
2. Run `npm install`.
3. Run `npm run check` before submitting a change.
4. Add or update a deliberately vulnerable fixture for scanner/parser changes.
5. Never commit a real credential, private vulnerable repository, or unredacted scanner output.

## Design rules

- Put deterministic scanning logic only in `cli/`.
- Keep the Action, MCP server, and agent adapters thin.
- Preserve stable schema fields and finding fingerprints.
- Add new host reasoning to the agent-review sidecar, not `findings.json`.
- Require human approval for external writes and application patches.
- Update the canonical skill and run `npm run sync:adapters`; do not hand-edit its copies.

## Adding a scanner

Implement the adapter interface, record applicability/availability/errors honestly, redact sensitive raw fields, normalize severity, add parser tests, and add an end-to-end fixture. A scanner error must never become zero findings.

By contributing, you agree that your contribution is licensed under MIT.

Maintainers should follow [`docs/RELEASING.md`](docs/RELEASING.md) for the protected npm bootstrap and subsequent staged releases.
