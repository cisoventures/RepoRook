# Local no-code service

RepoRook Service is an optional local dashboard for people who prefer buttons and plain English to terminal commands. It uses the same CLI and artifacts as the Action and MCP server; it is not a second scanner implementation.

## Start it

Requirements: Node.js 20 or later and the scanners appropriate for the repository.

```bash
npx --yes @reporook/service@latest --repo .
```

The command prints a private URL such as `http://127.0.0.1:7377/#token=...`. Open it on the same machine. The fragment token is not sent in the initial HTTP request; dashboard JavaScript exchanges it for an HTTP-only, same-site session cookie and removes it from the address bar.

The dashboard can:

- detect the project and create a conservative `reporook.yml` after confirmation;
- run the same fail-closed RepoRook scan used by the CLI;
- show reduced, plain-English finding evidence and coverage status;
- prepare a finding-bound remediation plan and exact proposal template;
- show the exact patch and tests supplied in that proposal;
- record a named approval receipt only if the proposal digest is unchanged.

It cannot install scanners, edit application code, apply a patch, push a branch, or create a pull request.

## Security boundary

The v0.7 local service:

- binds only to the literal loopback addresses `127.0.0.1` or `::1`;
- checks the `Host` header and same-origin header on mutations;
- uses a random bootstrap token and random in-memory session;
- applies a restrictive Content Security Policy and disables framing;
- limits request bodies to 64 KiB and read artifacts to 10 MiB;
- rejects `.reporook` artifact paths containing symbolic links;
- does not return raw scanner metadata, matched source, or secret material;
- never treats scanner exit code `2` as a completed scan;
- hashes the exact proposal file and rejects stale approvals.

Treat the printed private URL as a credential for the running process. Stop the service with Ctrl+C when finished. Do not expose this preview through a public tunnel or reverse proxy. Remote access belongs behind the future GitHub App's authenticated, TLS-protected deployment boundary.

## Development

```bash
npm run build --workspace @reporook/service
npm run test --workspace @reporook/service
node service/dist/index.js --repo . --port 7377
```
