# Infrastructure, container, and Git-history scanning

RepoRook v0.6 adds three intentionally different scopes while preserving the same normalized findings, coverage, policy, approval, and verification contracts.

## Repository infrastructure and workflows

Checkov becomes applicable automatically when RepoRook detects Terraform, Kubernetes, Helm, Kustomize, Dockerfile, or `.github/workflows` files. It scans only those local frameworks. RepoRook supplies an empty trusted Checkov configuration and disables result uploads, Prisma policy downloads, external Terraform module downloads, and inherited API tokens so a repository cannot silently broaden the scanner's behavior.

Offline Checkov policies do not consistently include severity. RepoRook keeps `raw_severity` empty and uses `medium` instead of inventing a stronger rating. To gate these findings at the default global `high` threshold, add a path policy such as:

```yaml
pathPolicies:
  infrastructure/**: medium
  .github/workflows/**: medium
```

## Explicit container images

RepoRook never guesses, builds, or pushes an image. Add up to 20 exact targets yourself:

```yaml
containerImages:
  - ghcr.io/example/api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
scanners:
  trivy-image: true
requiredScanners:
  - trivy-image
```

Trivy may use a local Docker-compatible image or pull from its configured registry sources. Pulling can require network access and registry credentials, so adding the target is an explicit scope decision. Prefer an immutable digest over a moving tag. Container findings remain visible in full and diff scans because they are external artifacts, not current repository paths.

## Opt-in Git history

The default Gitleaks mode scans current repository contents. Enable commit-history scanning only when intended:

```yaml
gitHistory: true
```

History scans can take longer and can report credentials from deleted files or old commits. RepoRook always invokes Gitleaks with full redaction and never normalizes the secret value. Safe commit provenance may be retained. In GitHub Actions, keep `actions/checkout` at `fetch-depth: 0`; a shallow checkout cannot provide complete history.

Historical findings remain visible in a diff scan because their source is an old commit rather than a current changed line. RepoRook omits current-file SARIF annotations and MCP code excerpts for them instead of presenting stale content as current evidence.

## Coverage behavior

An applicable missing or crashed scanner makes coverage partial or failed. `--require-scanners` turns any applicable scanner failure into exit `2`. `trivy-image` is non-applicable when `containerImages` is empty, and configuration rejects making it required without at least one target.
