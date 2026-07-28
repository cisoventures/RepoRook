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

test("fix verification rejects a Semgrep finding moved to another file", () => {
  const verificationFingerprint = `sha256:${"c".repeat(64)}`;
  const before = { ...original, verification_fingerprint: verificationFingerprint };
  const moved = { ...original, id: "rr-cccccccccccc", fingerprint: `sha256:${"d".repeat(64)}`, verification_fingerprint: verificationFingerprint, file: "src/moved.js" };
  const result = verifyFindingResolution(report({ findings: [before] }), report({ findings: [moved] }), before.id);
  assert.equal(result.scanner_resolution, "failed");
  assert.equal(result.remaining_finding.file, "src/moved.js");
});

test("legacy verification is inconclusive when same-rule relocation cannot be ruled out", () => {
  const moved = { ...original, id: "rr-dddddddddddd", fingerprint: `sha256:${"d".repeat(64)}`, file: "src/moved.js" };
  const result = verifyFindingResolution(report(), report({ findings: [moved] }), original.id);
  assert.equal(result.scanner_resolution, "inconclusive");
  assert.match(result.reason, /relocation cannot be ruled out/);
});

test("different Semgrep evidence remains inconclusive when same-rule relocation cannot be ruled out", () => {
  const before = { ...original, verification_fingerprint: `sha256:${"c".repeat(64)}` };
  const unrelated = { ...original, id: "rr-eeeeeeeeeeee", fingerprint: `sha256:${"e".repeat(64)}`, verification_fingerprint: `sha256:${"f".repeat(64)}`, file: "src/moved.js" };
  const result = verifyFindingResolution(report({ findings: [before] }), report({ findings: [unrelated] }), before.id);
  assert.equal(result.scanner_resolution, "inconclusive");
  assert.equal(result.remaining_finding.id, unrelated.id);
  assert.match(result.reason, /relocation cannot be ruled out/);
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
