import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { codeContext, findingContext, readReport } from "../dist/context.js";

function validReport(target, findings = []) {
  const now = "2026-07-28T12:00:00.000Z";
  const scannerNames = [...new Set(findings.map((finding) => finding.scanner))];
  if (!scannerNames.length) scannerNames.push("semgrep");
  const scanners = scannerNames.map((name) => ({ name, applicable: true, available: true, version: "1", status: "ok", finding_count: findings.filter((finding) => finding.scanner === name).length, duration_ms: 1 }));
  const summary = { critical: 0, high: 0, medium: 0, low: 0, total: findings.length };
  for (const finding of findings) summary[finding.severity] += 1;
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: "0.9.1" },
    target: { path: target, commit: null },
    generated_at: now,
    coverage_status: "complete",
    summary,
    scanners,
    findings,
    scan_receipt: { target, commit: null, config_hash: `sha256:${"a".repeat(64)}`, scanner_versions: Object.fromEntries(scanners.map((scanner) => [scanner.name, scanner.version])), started_at: now, completed_at: now },
  };
}

test("code context remains inside repository", async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-mcp-"));
  await mkdir(join(root, "src"));
  await writeFile(join(root, "src", "app.js"), "one\ntwo\nthree\n");
  try {
    const result = await codeContext(root, { id: "rr-test", file: "src/app.js", line: 2, description: "x", remediation_hint: "y" }, 1);
    assert.match(result.code, /2 \| two/);
    await assert.rejects(() => codeContext(root, { id: "rr-test", file: "../secret", line: 1, description: "x", remediation_hint: "y" }, 1));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("external and historical findings do not pretend current source context exists", async () => {
  const finding = { id: "rr-test", file: "container-image:example/app:1", line: 1, description: "x", remediation_hint: "y", metadata: { target_kind: "container-image" } };
  assert.equal(await findingContext("/tmp/repository", finding), null);
});

test("Gitleaks findings never return current source context", async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-mcp-secret-context-"));
  try {
    await writeFile(join(root, ".env"), "TOKEN=CURRENT_SECRET_VALUE\n");
    const finding = { id: "rr-aaaaaaaaaaaa", scanner: "gitleaks", rule: "generic-api-key", severity: "critical", file: ".env", line: 1, plain_summary: "Secret", description: "Secret", remediation_hint: "Rotate", fingerprint: `sha256:${"a".repeat(64)}`, references: [], metadata: { cwe: ["CWE-798"], cve: [], package: null, raw_severity: "secret" } };
    assert.equal(await findingContext(root, finding), null);
    const ordinary = { ...finding, scanner: "semgrep", rule: "ordinary" };
    assert.match((await findingContext(root, ordinary, 1)).code, /TOKEN=CURRENT_SECRET_VALUE/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("MCP evidence reads stay inside the repository and reject symbolic links", async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-mcp-report-"));
  const outside = join(tmpdir(), `reporook-mcp-outside-${process.pid}.json`);
  try {
    await mkdir(join(root, ".reporook"));
    const report = validReport(root);
    await writeFile(join(root, ".reporook", "findings.json"), `${JSON.stringify(report)}\n`);
    assert.deepEqual(await readReport(root, ".reporook/findings.json"), report);
    await writeFile(join(root, ".reporook", "forged.json"), "{}\n");
    await assert.rejects(readReport(root, ".reporook/forged.json"), /schema_version is required/);
    await writeFile(outside, "{\"secret\":true}\n");
    await assert.rejects(readReport(root, outside), /outside the repository/);
    if (process.platform !== "win32") {
      await symlink(outside, join(root, ".reporook", "linked.json"));
      await assert.rejects(readReport(root, ".reporook/linked.json"), /symbolic link/);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { force: true });
  }
});

test("MCP source context rejects linked and oversized repository files", async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-mcp-source-"));
  const outside = join(tmpdir(), `reporook-mcp-source-outside-${process.pid}.txt`);
  try {
    await mkdir(join(root, "src"));
    await writeFile(join(root, "src", "large.js"), "x".repeat(1024 * 1024 + 1));
    await assert.rejects(
      codeContext(root, { id: "rr-test", file: "src/large.js", line: 1, description: "x", remediation_hint: "y" }, 1),
      /1 MiB limit/,
    );
    if (process.platform !== "win32") {
      await writeFile(outside, "do not expose\n");
      await symlink(outside, join(root, "src", "linked.js"));
      await assert.rejects(
        codeContext(root, { id: "rr-test", file: "src/linked.js", line: 1, description: "x", remediation_hint: "y" }, 1),
        /symbolic link/,
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { force: true });
  }
});
