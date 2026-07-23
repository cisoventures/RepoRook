import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SemgrepScanner, parseSemgrep, semgrepErrors } from "../dist/scanners/semgrep.js";
import { parseGitleaks } from "../dist/scanners/gitleaks.js";
import { parseNpmAudit } from "../dist/scanners/npm-audit.js";
import { parsePipAudit } from "../dist/scanners/pip-audit.js";
import { discoverOsvLockfiles, OsvScanner, parseOsvScanner } from "../dist/scanners/osv-scanner.js";
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

test("Semgrep adapter fails closed on nonzero partial output", { skip: process.platform === "win32" }, async () => {
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

test("OSV-Scanner groups aliases into one actionable dependency finding", () => {
  const findings = parseOsvScanner({ results: [{
    source: { path: "/repo/Cargo.lock", type: "lockfile" },
    packages: [{
      package: { name: "regex", version: "1.5.1", ecosystem: "crates.io" },
      groups: [{ ids: ["GHSA-test-0000-0000", "RUSTSEC-2022-0001"], aliases: ["CVE-2022-0001", "GHSA-test-0000-0000"], max_severity: "9.8" }],
      vulnerabilities: [{
        id: "GHSA-test-0000-0000", aliases: ["CVE-2022-0001"], summary: "Regex denial of service",
        database_specific: { severity: "HIGH", cwe_ids: ["CWE-1333"] },
        affected: [{ package: { name: "regex" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "1.5.5" }] }] }],
        references: [{ url: "https://example.test/advisory" }],
      }, { id: "RUSTSEC-2022-0001", aliases: ["GHSA-test-0000-0000", "CVE-2022-0001"] }],
    }],
  }] }, "/repo");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "critical");
  assert.equal(findings[0].file, "Cargo.lock");
  assert.equal(findings[0].metadata.package, "regex");
  assert.deepEqual(findings[0].metadata.fixed_versions, ["1.5.5"]);
  assert.deepEqual(findings[0].metadata.cve, ["CVE-2022-0001"]);
  assert.deepEqual(findings[0].metadata.cwe, ["CWE-1333"]);
  assert.match(findings[0].plain_summary, /regex package/);
  assert.deepEqual(findings[0].references, [
    "https://osv.dev/vulnerability/GHSA-test-0000-0000",
    "https://example.test/advisory",
  ]);
});

test("OSV-Scanner discovers complementary root and nested manifests without generated dependency trees", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-osv-discovery-test-"));
  try {
    await mkdir(join(target, "services", "api"), { recursive: true });
    await mkdir(join(target, "node_modules", "ignored"), { recursive: true });
    await writeFile(join(target, "package-lock.json"), "{}");
    await writeFile(join(target, "requirements.txt"), "urllib3==1.0\n");
    await writeFile(join(target, "Cargo.lock"), "version = 3\n");
    await writeFile(join(target, "services", "api", "package-lock.json"), "{}");
    await writeFile(join(target, "node_modules", "ignored", "Cargo.lock"), "version = 3\n");
    const lockfiles = (await discoverOsvLockfiles(target)).map((file) => file.slice(target.length + 1).replaceAll("\\", "/"));
    assert.deepEqual(lockfiles, ["Cargo.lock", "services/api/package-lock.json"]);
  } finally {
    await rm(target, { recursive: true, force: true });
  }
});

test("OSV-Scanner treats exit 1 as a completed scan with findings", { skip: process.platform === "win32" }, async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-osv-adapter-test-"));
  const executable = join(target, "osv-scanner");
  const previousPath = process.env.PATH;
  await writeFile(join(target, "Cargo.lock"), "version = 3\n");
  await writeFile(executable, `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\\n' 'osv-scanner 2.3.8'
  exit 0
fi
printf '%s\\n' '{"results":[{"source":{"path":"Cargo.lock","type":"lockfile"},"packages":[{"package":{"name":"regex","version":"1.5.1","ecosystem":"crates.io"},"groups":[{"ids":["RUSTSEC-1"],"max_severity":"7.5"}],"vulnerabilities":[{"id":"RUSTSEC-1","summary":"Example advisory"}]}]}]}'
exit 1
`);
  await chmod(executable, 0o755);
  process.env.PATH = `${target}:${previousPath ?? ""}`;
  try {
    const result = await new OsvScanner().run({ target, config: structuredClone(defaultConfig) });
    assert.equal(result.status.status, "ok");
    assert.equal(result.status.finding_count, 1);
    assert.equal(result.findings[0].scanner, "osv-scanner");
  } finally {
    process.env.PATH = previousPath;
    await rm(target, { recursive: true, force: true });
  }
});
