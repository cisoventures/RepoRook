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
- record a named approval receipt only if the proposal digest is unchanged;
- optionally publish that exact approved patch as a draft pull request through a repository-scoped GitHub App installation token.

It cannot install scanners or edit the local application working tree. GitHub publishing is disabled unless it is explicitly configured at startup, and publishing requires a separate confirmation after exact-proposal approval.

## Repository-scoped draft pull requests

The optional publisher deliberately does not accept a personal access token. Provide a short-lived GitHub App installation access token through the environment and name one target repository on the command line:

```bash
export REPOROOK_GITHUB_TOKEN="SHORT_LIVED_INSTALLATION_TOKEN"
npx --yes @reporook/service@latest --repo . --github-repo OWNER/REPOSITORY
```

Install the App on **only the selected repository**, not every repository in an organization. The App needs repository metadata read access, contents read/write access, and pull-request read/write access. RepoRook verifies the token through GitHub's installation-repositories endpoint and rejects the operation if the selected repository is not visible. It never falls back to a broader personal token.

Before any GitHub write, RepoRook:

1. revalidates the approval receipt against the exact plan, source scan, patch, file list, and tests;
2. requires the approved scan commit to equal the selected repository's current default-branch commit;
3. downloads only the approved files from that commit and applies the text patch in a temporary directory;
4. rejects binary patches, renames, copies, symbolic links, submodules, special files, oversized patches, and oversized results;
5. creates an isolated `reporook/...` commit and branch, then opens a **draft** pull request.

The token is kept only in process memory and is never returned to the browser or written to a RepoRook artifact. The exact patch is uploaded only after the user clicks the separate draft-PR confirmation. CI and a human review still decide whether the draft is safe to merge.

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
- hashes the exact proposal file and rejects stale approvals;
- keeps the GitHub token server-side and accepts only an installation token authorized for the selected repository;
- refuses draft-PR publication when the default branch moved after the approved scan;
- applies approved text patches only in a disposable staging directory, never the local working tree.

Treat the printed private URL and installation token as credentials for the running process. Stop the service with Ctrl+C when finished. Do not expose this preview through a public tunnel or reverse proxy. Hosted access and a friendly App installation flow belong behind a future authenticated, TLS-protected deployment boundary.

## Development

```bash
npm run build --workspace @reporook/service
npm run test --workspace @reporook/service
node service/dist/index.js --repo . --port 7377
```
