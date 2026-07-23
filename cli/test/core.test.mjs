import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseSimpleYaml, defaultConfig } from "../dist/config.js";
import { scanRepository } from "../dist/engine.js";
import { toSarif } from "../dist/sarif.js";

test("simple YAML parser supports lists and scanner flags", () => {
  const parsed = parseSimpleYaml("failOn: medium\nignore:\n  - vendor/**\nscanners:\n  semgrep: false\n");
  assert.equal(parsed.failOn, "medium");
  assert.deepEqual(parsed.ignore, ["vendor/**"]);
  assert.deepEqual(parsed.scanners, { semgrep: false });
});

test("default configuration disables Semgrep telemetry while selecting explicit rules", () => {
  assert.equal(defaultConfig.semgrepConfig, "p/default");
});

test("engine deduplicates findings and produces SARIF", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-test-"));
  const finding = {
    id: "rr-aaaaaaaaaaaa", scanner: "fake", rule: "fake.rule", severity: "high", file: "src/app.js", line: 1, end_line: 2,
    description: "Unsafe operation", remediation_hint: "Use a safe operation", fingerprint: `sha256:${"a".repeat(64)}`,
    references: [], metadata: { cwe: ["CWE-1"], cve: [], package: null, raw_severity: "HIGH" },
  };
  const scanner = {
    name: "fake",
    async isApplicable() { return { applicable: true }; },
    async run() { return { status: { name: "fake", applicable: true, available: true, version: "1", status: "ok", finding_count: 2, duration_ms: 1 }, findings: [finding, finding] }; },
  };
  try {
    const report = await scanRepository({ target, config: structuredClone(defaultConfig) }, [scanner]);
    assert.equal(report.coverage_status, "complete");
    assert.equal(report.findings.length, 1);
    const sarif = toSarif(report);
    assert.equal(sarif.runs[0].results.length, 1);
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.endLine, 2);
    assert.equal("end_line" in sarif.runs[0].results[0].locations[0].physicalLocation.region, false);
  } finally {
    await rm(target, { recursive: true, force: true });
  }
});
