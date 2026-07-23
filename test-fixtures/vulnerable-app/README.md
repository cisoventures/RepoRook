# Intentionally vulnerable fixture

This directory exists only for RepoRook end-to-end tests. Do not deploy, copy, or use its credentials or dependency versions.

The dependency manifests are stored under `fixture-manifests/` with deliberately nonstandard names. This prevents GitHub's dependency graph from treating known-vulnerable test data as production dependencies. Materialize the ignored scanner inputs before a local fixture scan:

```bash
npm run fixture:prepare
node cli/dist/index.js scan test-fixtures/vulnerable-app --require-scanners
```

Never commit the generated `package.json`, `package-lock.json`, or `requirements.txt` files.
