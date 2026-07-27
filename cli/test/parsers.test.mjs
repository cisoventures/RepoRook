import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SemgrepScanner, parseSemgrep, semgrepErrors } from "../dist/scanners/semgrep.js";
import { GitleaksScanner, parseGitleaks } from "../dist/scanners/gitleaks.js";
import { CheckovScanner, parseCheckov } from "../dist/scanners/checkov.js";
import { parseTrivyImage, TrivyImageScanner } from "../dist/scanners/trivy-image.js";
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

test("Gitleaks history findings retain only safe commit provenance", () => {
  const findings = parseGitleaks([{ RuleID: "generic-api-key", File: "/repo/old.env", StartLine: 3, Secret: "DO_NOT_KEEP_ME", Commit: "a".repeat(40), Fingerprint: "abc:3", Description: "API key" }], "/repo", true);
  assert.equal(findings[0].metadata.target_kind, "git-history");
  assert.equal(findings[0].metadata.source_commit, "a".repeat(40));
  assert.doesNotMatch(JSON.stringify(findings), /DO_NOT_KEEP_ME/);
});

test("Gitleaks history mode is explicit and invokes the history command", { skip: process.platform === "win32" }, async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-gitleaks-history-test-"));
  const executable = join(target, "gitleaks");
  const argsPath = join(target, "args.txt");
  const previousPath = process.env.PATH;
  const previousArgsPath = process.env.REPOROOK_GITLEAKS_TEST_ARGS;
  await writeFile(executable, `#!/bin/sh
if [ "$1" = "--version" ]; then printf '%s\\n' 'gitleaks 8.28.0'; exit 0; fi
previous=""
report=""
for value in "$@"; do
  if [ "$previous" = "--report-path" ]; then report="$value"; fi
  previous="$value"
done
printf '%s\\n' "$*" > "$REPOROOK_GITLEAKS_TEST_ARGS"
printf '%s\\n' '[]' > "$report"
exit 0
`);
  await chmod(executable, 0o755);
  process.env.PATH = `${target}:${previousPath ?? ""}`;
  process.env.REPOROOK_GITLEAKS_TEST_ARGS = argsPath;
  try {
    const config = structuredClone(defaultConfig);
    config.gitHistory = true;
    const result = await new GitleaksScanner().run({ target, config });
    assert.equal(result.status.status, "ok");
    assert.match(await readFile(argsPath, "utf8"), /^git /);
  } finally {
    process.env.PATH = previousPath;
    if (previousArgsPath === undefined) delete process.env.REPOROOK_GITLEAKS_TEST_ARGS;
    else process.env.REPOROOK_GITLEAKS_TEST_ARGS = previousArgsPath;
    await rm(target, { recursive: true, force: true });
  }
});

test("Gitleaks malformed report output fails coverage instead of looking clean", { skip: process.platform === "win32" }, async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-gitleaks-malformed-test-"));
  const executable = join(target, "gitleaks");
  const previousPath = process.env.PATH;
  await writeFile(executable, `#!/bin/sh
if [ "$1" = "--version" ]; then printf '%s\\n' 'gitleaks 8.28.0'; exit 0; fi
previous=""
report=""
for value in "$@"; do
  if [ "$previous" = "--report-path" ]; then report="$value"; fi
  previous="$value"
done
printf '%s\\n' '{"unexpected":true}' > "$report"
exit 0
`);
  await chmod(executable, 0o755);
  process.env.PATH = `${target}:${previousPath ?? ""}`;
  try {
    const result = await new GitleaksScanner().run({ target, config: structuredClone(defaultConfig) });
    assert.equal(result.status.status, "error");
    assert.equal(result.status.finding_count, 0);
    assert.match(result.status.reason, /must be a JSON array/);
  } finally {
    process.env.PATH = previousPath;
    await rm(target, { recursive: true, force: true });
  }
});

test("Checkov output becomes a repository-relative infrastructure finding", () => {
  const findings = parseCheckov({
    check_type: "terraform",
    results: { failed_checks: [{
      check_id: "CKV_AWS_18",
      check_name: "Ensure the S3 bucket has access logging enabled",
      file_abs_path: "/repo/infrastructure/main.tf",
      file_line_range: [2, 8],
      resource: "aws_s3_bucket.logs",
      guideline: "https://example.test/checkov/CKV_AWS_18",
    }] },
  }, "/repo");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].scanner, "checkov");
  assert.equal(findings[0].file, "infrastructure/main.tf");
  assert.equal(findings[0].severity, "medium");
  assert.match(findings[0].plain_summary, /security safeguard/);
});

test("Trivy image output preserves image provenance and fixed versions", () => {
  const findings = parseTrivyImage({ Results: [{ Target: "alpine:3.17 (alpine 3.17.0)", Type: "alpine", Vulnerabilities: [{
    VulnerabilityID: "CVE-2026-0001",
    PkgName: "libssl3",
    InstalledVersion: "3.0.1",
    FixedVersion: "3.0.2, 3.0.3",
    Severity: "HIGH",
    Title: "Example TLS flaw",
    CweIDs: ["CWE-295"],
    PrimaryURL: "https://example.test/CVE-2026-0001",
  }] }] }, "registry.example.test/app@sha256:abc");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].scanner, "trivy-image");
  assert.equal(findings[0].metadata.target_kind, "container-image");
  assert.equal(findings[0].metadata.target, "registry.example.test/app@sha256:abc");
  assert.deepEqual(findings[0].metadata.fixed_versions, ["3.0.2", "3.0.3"]);
  assert.equal(findings[0].severity, "high");
});

test("Checkov and Trivy adapters treat scanner findings as completed runs", { skip: process.platform === "win32" }, async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-infrastructure-adapter-test-"));
  const previousPath = process.env.PATH;
  const checkov = join(target, "checkov");
  const checkovArgsPath = join(target, "checkov-args.txt");
  const trivy = join(target, "trivy");
  const trivyArgsPath = join(target, "trivy-args.txt");
  await writeFile(checkov, `#!/bin/sh
if [ "$1" = "--version" ]; then printf '%s\\n' '3.3.8'; exit 0; fi
if [ "\${BC_API_KEY+x}" = "x" ]; then exit 5; fi
printf '%s\\n' "$*" > "$REPOROOK_CHECKOV_TEST_ARGS"
case " $* " in *" --skip-results-upload "*) exit 4 ;; esac
previous=""
config=""
for value in "$@"; do
  if [ "$previous" = "--config-file" ]; then config="$value"; fi
  previous="$value"
done
test -n "$config" || exit 6
test "$(cat "$config")" = "{}" || exit 7
printf '%s\\n' '{"check_type":"dockerfile","results":{"failed_checks":[{"check_id":"CKV_DOCKER_3","check_name":"Ensure that a user for the container has been created","file_abs_path":"${target}/Dockerfile","file_line_range":[1,2],"resource":"Dockerfile.test"}]}}'
exit 1
`);
  await writeFile(trivy, `#!/bin/sh
if [ "$1" = "--version" ]; then printf '%s\\n' 'Version: 0.72.0'; exit 0; fi
printf '%s\\n' "$*" > "$REPOROOK_TRIVY_TEST_ARGS"
printf '%s\\n' '{"Results":[{"Target":"example/app:1","Type":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0002","PkgName":"busybox","InstalledVersion":"1","FixedVersion":"2","Severity":"CRITICAL"}]}]}'
exit 0
`);
  await Promise.all([chmod(checkov, 0o755), chmod(trivy, 0o755), writeFile(join(target, "Dockerfile"), "FROM alpine:3.17\n")]);
  process.env.PATH = `${target}:${previousPath ?? ""}`;
  const previousCheckovArgsPath = process.env.REPOROOK_CHECKOV_TEST_ARGS;
  const previousTrivyArgsPath = process.env.REPOROOK_TRIVY_TEST_ARGS;
  const previousCheckovApiKey = process.env.BC_API_KEY;
  process.env.REPOROOK_CHECKOV_TEST_ARGS = checkovArgsPath;
  process.env.REPOROOK_TRIVY_TEST_ARGS = trivyArgsPath;
  process.env.BC_API_KEY = "must-not-reach-checkov";
  try {
    const config = structuredClone(defaultConfig);
    config.containerImages = ["example/app:1"];
    const checkovResult = await new CheckovScanner().run({ target, config });
    const trivyResult = await new TrivyImageScanner().run({ target, config });
    assert.equal(checkovResult.status.status, "ok");
    assert.equal(checkovResult.findings[0].scanner, "checkov");
    assert.equal(trivyResult.status.status, "ok");
    assert.equal(trivyResult.findings[0].scanner, "trivy-image");
    const checkovArgs = await readFile(checkovArgsPath, "utf8");
    assert.match(checkovArgs, /--skip-download/);
    assert.match(checkovArgs, /--config-file/);
    assert.doesNotMatch(checkovArgs, /--skip-results-upload/);
    assert.match(await readFile(trivyArgsPath, "utf8"), /--cache-dir .*reporook-trivy-/);
  } finally {
    process.env.PATH = previousPath;
    if (previousCheckovArgsPath === undefined) delete process.env.REPOROOK_CHECKOV_TEST_ARGS;
    else process.env.REPOROOK_CHECKOV_TEST_ARGS = previousCheckovArgsPath;
    if (previousTrivyArgsPath === undefined) delete process.env.REPOROOK_TRIVY_TEST_ARGS;
    else process.env.REPOROOK_TRIVY_TEST_ARGS = previousTrivyArgsPath;
    if (previousCheckovApiKey === undefined) delete process.env.BC_API_KEY;
    else process.env.BC_API_KEY = previousCheckovApiKey;
    await rm(target, { recursive: true, force: true });
  }
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
