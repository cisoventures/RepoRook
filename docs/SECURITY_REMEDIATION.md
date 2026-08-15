# v1 independent-review remediation

An independent reviewer assessed RepoRook at revision `11f6b1b` and reported 32 tracked IDs: 29 validated or related items, two plausible items that could not be fully exercised on the review platform, and one withdrawn item. The security implementation is anchored at `d4efe3df3cedb49c7af7bc5162fca820be8684aa`; the v1 version, documentation, and final regression changes follow on the same remediation branch.

This is a remediation ledger, not a self-issued security opinion. The initial review is complete; v1 publication remains gated on the independent reviewer verifying the final branch and the protected CI/release checks.

## Remediation ledger

| ID | Outcome | Control and regression evidence |
|---|---|---|
| RR-COV-01 | Fixed | `npm audit` operational-error documents and malformed advisory sections fail scanner coverage; the adapter and engine path are exercised in `cli/test/parsers.test.mjs`. |
| RR-COV-02 | Fixed | The Action deletes owned stale evidence, emits every output with a fresh random delimiter, and coerces policy counts to non-negative integers; hostile last-wins output simulation lives in `action/run-scan.test.mjs`. |
| RR-COV-03 | Fixed | Fixture verification, guided-fix, and policy gates run independently of the optional Python scanner lock; `action/supply-chain-policy.test.mjs` prevents the skip from returning. |
| RR-EVD-01 | Fixed | Findings require repository-path-bound HMAC authentication plus strict schema reconstruction before CLI, MCP, or service use; forged and cross-target evidence tests live in `cli/test/auth.test.mjs` and MCP/service boundary suites. |
| RR-EVD-02 | Fixed | Gitleaks preserves occurrence identity while retaining a separate relocation-tolerant verification fingerprint; parser regressions cover multiple occurrences. |
| RR-EVD-03 | Fixed | Suppression IDs are recomputed, bind the full finding fingerprint, and cannot affect policy without trusted invocation opt-in; `cli/test/policy.test.mjs` covers tampering and default denial. |
| RR-EVD-04 | Fixed | `finding_count` is recalculated after filtering and deduplication, and genuine output passes the same strict parser used by consumers. |
| RR-APR-01 | Fixed | The dashboard refuses to display or approve a patch over the complete-rendering limit; it never truncates one patch while publishing another. |
| RR-APR-02 | Fixed | Approval attribution and all exact proposal bindings are covered by a host-local, repository-bound HMAC; a forged public approval ID still fails `cli/test/approval.test.mjs`. |
| RR-APR-03 | Fixed | The service sends the SHA-256 digest of the exact raw proposal shown, and the CLI verifies that digest immediately before parsing and signing it. |
| RR-MCP-01 | Fixed | MCP validates bounded single-line arguments, places positional values after `--`, and emits arbitrary flags inline; option-like repository and revision regressions exercise the boundary. |
| RR-MCP-02 | Fixed | MCP handler errors remove absolute filesystem paths and control characters before returning bounded client text. |
| RR-MCP-03 | Fixed | A canonical-path lock rejects concurrent scans of one repository before evidence writes can interleave. |
| RR-FS-01 | Fixed; Windows revalidation requested | Bare commands resolve through a sanitized absolute search path and Windows resolution excludes the scanned working directory. The deterministic Windows-path test runs cross-platform; final Windows CI and independent Windows exercise remain required. |
| RR-FS-02 | Fixed | Repository configuration cannot choose non-default Semgrep rules. A trusted invocation selects rules, non-default network sources require external authorization, and local files are canonical-path and digest bound. |
| RR-FS-03 | Fixed | Python requirements discovery and aggregate adapter runtime are capped, preventing repository-controlled process multiplication. |
| RR-FS-04 | Fixed | Scan output is fixed to `.reporook`, rejects `.git`, clears owned stale artifacts, and artifact consumers use bounded no-follow reads. |
| RR-FS-05 | Fixed | Checkov fallback paths pass through the same repository-relative containment helper as other parser paths. |
| RR-FS-06 | Fixed | OSV discovery has depth, entry, result, and aggregate argument-size limits that fail closed. |
| RR-AGT-01 | Fixed | Per-host validation and remediation assertions inspect declared host surfaces without concatenating the canonical skill into the result. |
| RR-AGT-02 | Fixed | The parity validator derives the installer specification and requires exact equality with each host's declared installed paths. |
| RR-AGT-03 | Fixed | Scanner-controlled fields and source context are control-character-neutralized and length bounded; every MCP response labels finding and source content as untrusted data that must never supply instructions. |
| RR-SVC-01 | Fixed; browser revalidation requested | Cookies were removed. A one-use fragment bootstrap creates a rotating bearer held in exact-origin `sessionStorage`; logout invalidates it. All 21 live loopback service tests pass, and independent browser exercise remains requested. |
| RR-SVC-02 | Fixed | GitHub App onboarding state is consumed in `finally` after success or failure, preventing failed-callback replay. |
| RR-SVC-03 | Fixed | The publisher requires `draft === true`; otherwise it closes the unexpected pull request, deletes the branch, and fails. |
| RR-REL-02 | Fixed | Validation and packaging run without OIDC or write permission; the privileged release job has no checkout and executes no repository source. |
| RR-REL-03 | Fixed | Release requires `GITHUB_SHA` to equal the GitHub API's exact current `main` commit before tagging or publishing. |
| RR-REL-04 | Fixed with RR-REL-03 | Dispatch and tag versions are independently format checked and must equal all package manifests in the unprivileged validation job. |
| RR-REL-05 | Fixed | Every published consumer example pins RepoRook and checkout by full commit SHA; the supply-chain test rejects mutable `uses:` references. |
| RR-REL-06 | Fixed | RepoRook's self-scan grants only `contents: read`, disables credential persistence, PR comments, and SARIF writes while executing pull-request code. |
| RR-REL-07 | Mitigated; manual residual accepted | The stage-only OIDC publisher cannot reject npm stages. On partial failure the workflow names all possible leftovers, and release guidance requires 2FA review/rejection before retry; no broad cleanup token was introduced. |
| RR-REL-01 | Withdrawn | The reviewer confirmed the tag and commit after refreshing stale local refs; no remediation was appropriate. |

## Required independent re-review

The re-review should start from a clean checkout of the final remediation branch and:

1. rerun the original proof for every non-withdrawn ID and show that the prior exploit or failure no longer succeeds;
2. run `npm run check`, `npm run smoke:packages`, and the live service suite with loopback tests required;
3. exercise RR-FS-01 on Windows and RR-SVC-01 in a real browser, preserving any remaining uncertainty rather than flattening it;
4. inspect the privileged release job and npm recovery path without adding publishing credentials; and
5. report any regression or new finding before recommending v1 publication.
