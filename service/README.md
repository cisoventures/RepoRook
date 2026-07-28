# @reporook/service

Local no-code RepoRook dashboard for onboarding, security scans, plain-English findings, guided plans, exact-proposal approval receipts, and optional repository-scoped draft pull requests.

```bash
reporook-service --repo .
```

The service binds only to loopback and prints a private tokenized URL. It uses the `reporook` CLI for deterministic operations and never modifies the local application working tree. If the repository has a `github.com` origin, click **Connect this repository** and follow GitHub's prompts. Select **Only select repositories**, then select the displayed repository.

RepoRook creates a private App without OAuth or webhooks and requests only metadata read, contents write, and pull-request write access. It verifies the installation against the exact repository and mints one-hour tokens narrowed to that repository. The advanced legacy path accepts an existing App installation token, but never a personal access token:

```bash
REPOROOK_GITHUB_TOKEN="..." reporook-service --repo . --github-repo OWNER/REPOSITORY
```

See the repository's [service guide](https://github.com/cisoventures/RepoRook/blob/main/docs/SERVICE.md) for credential storage, the exact publishing boundary, and recovery steps.
