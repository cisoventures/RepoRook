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

## Fuzzing contract

`cli/test/fuzz.test.mjs` is deterministic so a failure is reproducible on Linux, macOS, and Windows. It generates nested arrays, objects, hostile paths, markup, null bytes, prototype-sensitive keys, unexpected scalar types, and secret-shaped fields. Scanner normalizers must return structurally valid findings without throwing. Strict policy and approval parsers may reject input, but rejection must be an ordinary bounded error and must not mutate global prototypes.

This seeded suite is a regression gate, not a substitute for coverage-guided native fuzzing or an external review. Later v0.9 slices will extend size limits to remaining evidence inputs, exercise hostile filesystem layouts end to end, document sandbox expectations for every subprocess, and prepare the external audit and coordinated response material.
