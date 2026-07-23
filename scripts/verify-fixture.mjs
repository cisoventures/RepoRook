import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const target = resolve(root, "test-fixtures/vulnerable-app");
const baselinePath = resolve(target, ".reporook/findings.json");
const before = await readFile(baselinePath, "utf8");
const baseline = JSON.parse(before);
const finding = baseline.findings.find((candidate) => candidate.scanner === "gitleaks") ?? baseline.findings[0];
if (!finding?.id) throw new Error("The vulnerable fixture did not produce a finding to verify");

const result = spawnSync(process.execPath, [
  resolve(root, "cli/dist/index.js"),
  "verify",
  finding.id,
  target,
  "--require-scanners",
  "--no-sarif",
  "--quiet",
], { encoding: "utf8" });
if (result.status !== 1) {
  throw new Error(`An unchanged finding must fail verification with exit 1, received ${result.status}: ${result.stderr}`);
}
const after = await readFile(baselinePath, "utf8");
if (after !== before) throw new Error("Verification overwrote the baseline findings artifact");

const receiptPath = resolve(target, `.reporook/verifications/${finding.id}/verification.json`);
const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
if (receipt.scanner_resolution !== "failed" || receipt.remaining_finding?.id !== finding.id) {
  throw new Error("Verification did not preserve the equivalent remaining finding");
}
if (receipt.functional_tests?.status !== "not-recorded") {
  throw new Error("RepoRook must not imply that it ran the repository's functional tests");
}
process.stdout.write(`Verified baseline preservation and failed resolution for ${finding.id}.\n`);
