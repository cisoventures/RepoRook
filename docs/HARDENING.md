# Hardening RepoRook

RepoRook treats the repository it scans, scanner output, policy evidence, host-agent messages, and external vulnerability data as inputs crossing trust boundaries. [`SECURITY.md`](../SECURITY.md) is the authoritative repository threat model and security policy. Hardening work must preserve its invariants and distinguish a RepoRook defect from a limitation in a third-party scanner or rule set.

## Hostile-repository baseline

A repository may contain malformed configuration, unusual filenames, symbolic links, deeply nested data, oversized files, adversarial glob patterns, scanner fixtures that resemble secrets, or content intended to manipulate an agent. RepoRook must handle those inputs as data and either produce bounded evidence or fail closed with exit `2`.

The first v0.9 controls enforce:

- configuration files remain inside the repository;
- every existing configuration path component is non-symbolic-link;
- configuration input is a regular file capped at 1 MiB;
- an explicitly selected missing configuration never falls back to defaults;
- YAML mapping keys cannot mutate JavaScript object prototypes;
- the YAML subset avoids quadratic remainder copies on large mapping inputs;
- scanner, policy, approval, and configuration parsers run against a seeded hostile JSON/YAML corpus in every test matrix job.

The second slice extends that boundary to evidence reuse and agent context:

- CLI findings, baseline, suppression, remediation, approval, and cache reads accept only regular non-link files, valid UTF-8, and at most 10 MiB;
- MCP report reads require an explicit repository root, stay inside it, reject every symbolic-link component, and use the same 10 MiB cap;
- MCP source context is repository-contained, non-symbolic-link, regular UTF-8 input capped at 1 MiB;
- MCP JSON-RPC messages are capped at 1 MiB, and CLI child output and runtime are capped at 50 MiB and 15 minutes;
- repository-local agent integration files are non-link regular UTF-8 inputs capped at 2 MiB, with a 1 MiB allowlisted ownership receipt;
- Gitleaks file output is capped at 50 MiB and malformed or unexpected JSON is scanner failure, never a clean result.

## Fuzzing contract

`cli/test/fuzz.test.mjs` is deterministic so a failure is reproducible on Linux, macOS, and Windows. It generates nested arrays, objects, hostile paths, markup, null bytes, prototype-sensitive keys, unexpected scalar types, and secret-shaped fields. Scanner normalizers must return structurally valid findings without throwing. Strict policy and approval parsers may reject input, but rejection must be an ordinary bounded error and must not mutate global prototypes.

The scanner execution and residual-risk review is documented in [`SANDBOXING.md`](SANDBOXING.md). The independent-review scope and coordinated response workflow are ready in [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) and [`SECURITY_RESPONSE.md`](SECURITY_RESPONSE.md). This seeded suite is a regression gate, not a substitute for coverage-guided native fuzzing or an actual independent review. Later v0.9 work will continue hostile-filesystem coverage and incorporate reviewer findings.
