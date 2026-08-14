# Compatibility and migration policy

RepoRook's v1 release-candidate contract is recorded in [`contracts/v1.json`](../contracts/v1.json) and checked by `npm run validate:contracts`. The contract makes accidental breaking changes fail in CI before they reach users. It becomes the stable v1 compatibility promise when v1.0 ships.

## Covered public surfaces

The compatibility gate covers:

- the names, binaries, entry points, files, Node.js engines, and runtime exports of `reporook`, `@reporook/mcp-server`, and `@reporook/service`;
- CLI commands, long flags, `--help`/`-h`, `--version`/`-v`, and exit-code meanings;
- MCP server identity, tool names, and normalized tool input schemas;
- accepted repository configuration keys, defaults, and scanner names;
- versioned evidence-schema identifiers and normalized schema contents;
- GitHub Action input defaults and output names; and
- the tested Node.js and operating-system matrix.

The current support floor is Node.js 20. CI tests Node.js 20 and 22 on Linux, macOS, and Windows.

Scanner rule accuracy, vulnerability-database contents, third-party scanner availability, native-agent product lifecycles, and a future hosted multi-user service are not frozen by this contract. Changes to those areas must still preserve RepoRook's evidence, coverage, and approval boundaries.

## Versioning after v1.0

RepoRook follows semantic versioning for the covered public surfaces:

- A patch release may fix behavior without changing a documented contract.
- A minor release may add optional fields, commands, flags, tools, exports, or Action inputs without changing existing behavior.
- Removing, renaming, reinterpreting, or making an optional input required needs a major release.

Before v1.0, an intentional release-candidate contract change must update the implementation, `contracts/v1.json`, relevant documentation, tests, and changelog in the same pull request. The compatibility failure is not a snapshot-update instruction: reviewers must decide whether the change is additive, a migration, or an unintended break.

## Deprecation and migration

After v1.0, a deprecated surface is announced in the changelog and its user-facing documentation. When practical, the old surface emits a clear warning and remains functional for at least one minor release. Removal occurs only in a major release.

An urgent security fix may shorten that period when retaining the behavior would expose users to material risk. The release notes must name the risk, the affected surface, and the safe replacement.

Each intentional breaking change must provide:

1. the old and new behavior;
2. who is affected and how to detect usage;
3. exact migration steps or a migration command;
4. any evidence-artifact or configuration transformation; and
5. a rollback path when one is technically safe.

RepoRook never silently rewrites repository configuration or stored evidence merely to make it match a new contract.

## Evidence schemas

The schema `$id` is the durable version boundary. Adding an optional field without changing existing meaning may be compatible. Removing a field, making a field required, narrowing accepted values, or changing meaning requires a new major schema identifier and documented migration. Readers should reject unsupported major schema versions rather than guessing.

## Security and approval boundary

MCP can prepare a remediation plan and verify a fix, but it intentionally cannot record approval. Approval is created at the trusted CLI or local-service boundary so an agent cannot approve its own patch. That omission is a security property, not a missing MCP feature.

CLI exit codes remain stable:

- `0`: complete coverage and no policy-actionable finding met the configured threshold;
- `1`: complete coverage and at least one policy-actionable finding met the configured threshold; and
- `2`: target, configuration, required-scanner, policy, or incomplete-coverage error.

Callers must not treat exit code `2` as a clean scan.

## Changing the contract intentionally

Run these checks before proposing a contract change:

```bash
npm run build
npm run validate:contracts
npm run check
```

Then update the contract snapshot only after reviewing the compatibility and migration impact. A pull request that changes `contracts/v1.json` should explain each changed public surface and link its migration guidance.
