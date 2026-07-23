import test from "node:test";
import assert from "node:assert/strict";
import { verifyFindingResolution } from "../dist/verification.js";

const original = {
  id: "rr-aaaaaaaaaaaa", fingerprint: `sha256:${"a".repeat(64)}`, scanner: "semgrep", rule: "rule.one", file: "src/app.js",
};
const report = ({ findings = [original], scannerStatus = "ok", hash = "sha256:config" } = {}) => ({
  findings,
  scanners: [{ name: "semgrep", status: scannerStatus, applicable: true }],
  scan_receipt: { config_hash: hash },
});

test("fix verification is inconclusive when the original scanner did not complete", () => {
  const result = verifyFindingResolution(report(), report({ findings: [], scannerStatus: "error" }), original.id);
  assert.equal(result.scanner_resolution, "inconclusive");
  assert.match(result.reason, /did not complete/);
});

test("fix verification is inconclusive after a configuration change", () => {
  const result = verifyFindingResolution(report(), report({ findings: [], hash: "sha256:changed" }), original.id);
  assert.equal(result.scanner_resolution, "inconclusive");
  assert.equal(result.config_unchanged, false);
});

test("fix verification rejects an equivalent finding with a changed fingerprint", () => {
  const equivalent = { ...original, id: "rr-bbbbbbbbbbbb", fingerprint: `sha256:${"b".repeat(64)}` };
  const result = verifyFindingResolution(report(), report({ findings: [equivalent] }), original.id);
  assert.equal(result.scanner_resolution, "failed");
  assert.equal(result.remaining_finding.id, equivalent.id);
});

test("fix verification passes only after the same scanner and configuration complete", () => {
  const result = verifyFindingResolution(report(), report({ findings: [] }), original.id);
  assert.equal(result.scanner_resolution, "passed");
  assert.equal(result.config_unchanged, true);
});

test("fix verification remains inconclusive when another required scanner failed", () => {
  const result = verifyFindingResolution(report(), report({ findings: [] }), original.id, true);
  assert.equal(result.scanner_resolution, "inconclusive");
  assert.match(result.reason, /required scanner did not complete/);
});
