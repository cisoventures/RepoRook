import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SemgrepScanner, parseSemgrep, semgrepErrors } from "../dist/scanners/semgrep.js";
import { parseGitleaks } from "../dist/scanners/gitleaks.js";
import { parseNpmAudit } from "../dist/scanners/npm-audit.js";
import { parsePipAudit } from "../dist/scanners/pip-audit.js";
import { findingFingerprint } from "../dist/fingerprint.js";
import { defaultConfig } from "../dist/config.js";

test("finding fingerprints are stable and line independent", () => {
  const first = findingFingerprint(["semgrep", "rule", "src/app.js", "dangerous code"]);
  const second = findingFingerprint(["semgrep", "rule", "src/app.js", "dangerous   code"]);
  assert.deepEqual(first, second);
  assert.match(first.id, /^rr-[a-f0-9]{12}$/);
});

test("Semgrep output maps to the normalized schema", () => {
  const findings = parseSemgrep({ results: [{
    check_id: "javascript.lang.security.audit.child-process-exec",
    path: "/repo/src/app.js",
    start: { line: 12, col: 3 }, end: { line: 12, col: 30 },
    extra: { severity: "ERROR", message: "Untrusted input reaches exec", lines: "exec(req.query.cmd)", metadata: { cwe: ["CWE-78"], confidence: "HIGH" } },
  }] }, "/repo");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].file, "src/app.js");
  assert.deepEqual(findings[0].metadata.cwe, ["CWE-78"]);
  assert.match(findings[0].plain_summary, /system command/);
});

test("Semgrep errors are surfaced separately from findings", () => {
  const raw = { results: [], errors: [{ message: "Could not parse src/broken.py" }] };
  assert.deepEqual(parseSemgrep(raw, "/repo"), []);
  assert.deepEqual(semgrepErrors(raw), ["Could not parse src/broken.py"]);
});

test("Semgrep adapter fails closed on nonzero partial output", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-semgrep-adapter-test-"));
  const executable = join(target, "semgrep");
  const previousPath = process.env.PATH;
  await writeFile(executable, `#!/bin/sh
if [ "$1" = "--version" ]; then
  test "$2" = "--disable-version-check" || exit 3
  printf '%s\\n' 'semgrep 1.2.3'
  exit 0
fi
printf '%s\\n' '{"results":[{"check_id":"test.partial","path":"app.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"severity":"ERROR","message":"Partial match","metadata":{}}}],"errors":[{"message":"Could not parse broken.py"}]}'
exit 1
`);
  await chmod(executable, 0o755);
  process.env.PATH = `${target}:${previousPath ?? ""}`;
  try {
    const result = await new SemgrepScanner().run({ target, config: structuredClone(defaultConfig) });
    assert.equal(result.status.status, "error");
    assert.equal(result.status.finding_count, 1);
    assert.match(result.status.reason, /Could not parse broken\.py/);
    assert.equal(result.findings.length, 1);
  } finally {
    process.env.PATH = previousPath;
    await rm(target, { recursive: true, force: true });
  }
});

test("Gitleaks parser never preserves secret material", () => {
  const findings = parseGitleaks([{ RuleID: "aws-access-token", File: "/repo/.env", StartLine: 1, Secret: "DO_NOT_KEEP_ME", Fingerprint: "abc:1", Description: "AWS key" }], "/repo");
  assert.equal(findings.length, 1);
  assert.doesNotMatch(JSON.stringify(findings), /DO_NOT_KEEP_ME/);
  assert.equal(findings[0].severity, "critical");
  assert.match(findings[0].plain_summary, /API key|token|password/);
});

test("npm audit v7 output becomes one advisory finding", () => {
  const findings = parseNpmAudit({ vulnerabilities: { lodash: { severity: "high", isDirect: true, via: [{ source: 123, title: "Prototype pollution", url: "https://example.test/123", severity: "high", cwe: ["CWE-1321"] }], fixAvailable: { version: "4.17.21" } } } });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].metadata.package, "lodash");
  assert.equal(findings[0].file, "package-lock.json");
  assert.match(findings[0].plain_summary, /lodash package/);
});

test("pip-audit output records fixed versions", () => {
  const findings = parsePipAudit({ dependencies: [{ name: "urllib3", version: "1.24.1", vulns: [{ id: "PYSEC-1", aliases: ["CVE-2020-0001"], fix_versions: ["1.25.9"], description: "Example issue" }] }] }, "requirements.txt");
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].metadata.fixed_versions, ["1.25.9"]);
  assert.deepEqual(findings[0].metadata.cve, ["CVE-2020-0001"]);
  assert.match(findings[0].plain_summary, /urllib3 package/);
});
