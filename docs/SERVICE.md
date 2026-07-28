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
- show a scanner-by-scanner coverage checklist and explain why an incomplete scan is inconclusive;
- display platform-specific scanner setup commands after an explicit click without running them or installing software;
- show reduced, plain-English finding evidence and coverage status;
- prepare a finding-bound remediation plan and exact proposal template;
- show the exact patch and tests supplied in that proposal;
- record a named approval receipt only if the proposal digest is unchanged;
- guide the user through connecting a private GitHub App to the detected repository;
- optionally publish that exact approved patch as a draft pull request through a one-hour, single-repository installation token.

It cannot install scanners or edit the local application working tree. GitHub publishing requires a separate confirmation after exact-proposal approval.

When coverage is partial or failed, use **Show scanner setup instructions** in the coverage card. RepoRook displays the same reviewed commands as `reporook setup`; it does not execute those commands. After installing the scanners you choose, run the dashboard scan again and confirm that every applicable check is marked **ready** before treating the result as a security gate.

## Repository-scoped draft pull requests

RepoRook detects `OWNER/REPOSITORY` from the local repository's `github.com` `origin`. If the project has no origin or uses a different remote, provide the target explicitly:

```bash
npx --yes @reporook/service@latest --repo . --github-repo OWNER/REPOSITORY
```

Then:

1. Open the private dashboard URL printed by RepoRook.
2. Click **Connect this repository**.
3. Review the target and three requested repository permissions, then click **Continue to GitHub**.
4. GitHub creates a private App owned by the signed-in user. Accept its generated name.
5. On the installation screen, choose **Only select repositories** and select the one repository displayed by RepoRook.
6. GitHub returns to the loopback dashboard. A green **connected** status confirms that RepoRook independently verified the installation against the target repository.

The manifest requests repository metadata read access, contents read/write access, and pull-request read/write access. It requests no account permissions, organization permissions, user OAuth authorization, webhook events, workflow-file permission, or public App listing. Even if the App is accidentally installed on additional repositories, every generated installation token is explicitly narrowed to the displayed repository and those three permissions. Select only the target repository anyway so GitHub's durable installation grant is narrow too.

GitHub documents that the `installation_id` in a setup callback can be spoofed. RepoRook does not trust it: the callback is tied to random, expiring in-memory state, and RepoRook signs an App JWT and asks GitHub which App installation owns the exact repository. A mismatch is rejected before the App key is stored or an installation token is minted.

The generated private key is stored outside the scanned repository so the connection survives a restart:

- macOS: `~/Library/Application Support/RepoRook/github-HASH.json`
- Linux: `$XDG_CONFIG_HOME/reporook/github-HASH.json`, or `~/.config/reporook/...`
- Windows: `%APPDATA%\RepoRook\github-HASH.json`

On POSIX systems the directory is mode `0700` and the credential file is mode `0600`; symbolic-link credential files are rejected. The file contains the App ID, installation ID, App slug, and private key. It never contains an installation token, webhook secret, client secret, repository content, finding, or patch. Installation tokens remain in process memory, are narrowed to one repository, and expire after one hour. **Disconnect local key** deletes this local file; uninstall the private App in GitHub settings as a separate cleanup step.

Workflow-file changes are intentionally outside the default permission set. If an exact proposal touches `.github/workflows`, GitHub may reject publication and the change must use a separately reviewed workflow with the additional GitHub Workflows permission.

### Advanced existing-token mode

Automation can still supply a short-lived GitHub App installation token and explicit repository. This bypasses the guided connection but not any publishing checks:

```bash
REPOROOK_GITHUB_TOKEN="SHORT_LIVED_INSTALLATION_TOKEN" \
  npx --yes @reporook/service@latest --repo . --github-repo OWNER/REPOSITORY
```

RepoRook verifies it through GitHub's installation-repositories endpoint and rejects the operation if the selected repository is not visible. A personal access token fails this installation-only check; there is no fallback to a broader credential.

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
- keeps GitHub App keys and tokens server-side, outside RepoRook artifacts and browser responses;
- uses random, expiring manifest state and validates the setup installation against the exact target repository;
- asks GitHub to mint installation tokens for the selected repository and reduced permissions only;
- refuses draft-PR publication when the default branch moved after the approved scan;
- applies approved text patches only in a disposable staging directory, never the local working tree.

Treat the printed private URL and locally stored App key as credentials. Stop the service with Ctrl+C when finished. Do not expose this loopback service through a public tunnel or reverse proxy. A remote multi-user service requires a separate authenticated, TLS-protected deployment boundary.

## Development

```bash
npm run build --workspace @reporook/service
npm run test --workspace @reporook/service
node service/dist/index.js --repo . --port 7377
```
