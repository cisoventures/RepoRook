# Beginner journey acceptance

RepoRook's v1.0 release gate includes one executable, beginner-grade journey rather than a collection of disconnected feature checks. Run it after building the workspaces:

```sh
npm run build
npm run fixture:journey
```

The CI fixture job sets `REPOROOK_REQUIRE_LOOPBACK_TESTS=1`, so an environment that cannot start the loopback-only dashboard fails instead of silently skipping the acceptance gate.

## What the harness proves

The deterministic fixture exercises the local service in the order a non-security user encounters it:

1. the private dashboard requires its bootstrap session;
2. initialization requires the exact confirmation and creates only repository-local configuration;
3. scanner setup returns reviewable instructions and explicitly reports that it did not install, download, execute, or modify anything;
4. an unavailable applicable scanner produces partial coverage, exit code `2`, no clean result, and scanner-specific recovery context;
5. a complete rescan exposes only redacted, plain-English evidence and a fix-now item;
6. the service prepares one finding-bound patch and functional plus same-scanner verification plan;
7. a stale proposal digest cannot be approved, while the exact proposal produces a durable approval receipt;
8. draft-PR publishing requires a separate confirmation and a one-repository GitHub App installation token;
9. the approved patch is materialized against the exact scanned commit in the simulated remote repository, while the local working tree remains unchanged; and
10. the resulting pull request is always a draft and carries the approved functional test and `reporook verify` commands for CI and human review.

The GitHub API is simulated in memory. The harness never contacts GitHub, npm, a scanner registry, or another repository, and it never installs software. Scanner-adapter correctness, hostile-input regression tests, and the live GitHub Action remain separate gates. This acceptance test does not replace the independent security review required for v1.0.
