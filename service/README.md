# @reporook/service

Local no-code RepoRook dashboard for onboarding, security scans, plain-English findings, guided plans, exact-proposal approval receipts, and optional repository-scoped draft pull requests.

```bash
npx --yes @reporook/service@latest --repo .
```

The service binds only to loopback and prints a private tokenized URL. It uses the `reporook` CLI for deterministic operations and never modifies the local application working tree.

Optional GitHub publishing requires a short-lived GitHub App installation token and an explicit repository:

```bash
REPOROOK_GITHUB_TOKEN="..." npx --yes @reporook/service@latest --repo . --github-repo OWNER/REPOSITORY
```

The App should be installed only on the selected repository. Personal access tokens are rejected. See the repository's [service guide](https://github.com/cisoventures/RepoRook/blob/main/docs/SERVICE.md) for the complete security boundary.
