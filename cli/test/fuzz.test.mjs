import test from "node:test";
import assert from "node:assert/strict";
import { normalizeConfig, parseOrganizationPolicy, parseSimpleYaml } from "../dist/config.js";
import { parseApprovalReceipt, parseRemediationProposal } from "../dist/approval.js";
import { parseFindingBaseline, parseSuppressionFile } from "../dist/policy.js";
import { parseSemgrep, semgrepErrors } from "../dist/scanners/semgrep.js";
import { parseGitleaks } from "../dist/scanners/gitleaks.js";
import { parseCheckov } from "../dist/scanners/checkov.js";
import { parseTrivyImage } from "../dist/scanners/trivy-image.js";
import { parseNpmAudit } from "../dist/scanners/npm-audit.js";
import { parsePipAudit } from "../dist/scanners/pip-audit.js";
import { parseOsvScanner } from "../dist/scanners/osv-scanner.js";

function random(seed = 0x5eedc0de) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}

const next = random();
const keys = [
  "results", "errors", "check_id", "path", "start", "end", "extra", "metadata", "message", "Secret", "Match",
  "RuleID", "File", "Commit", "vulnerabilities", "via", "dependencies", "vulns", "Results", "Vulnerabilities",
  "failed_checks", "source", "packages", "package", "groups", "ids", "aliases", "affected", "ranges", "events",
  "__proto__", "prototype", "constructor", "x\0y", "../outside", "",
];
const strings = [
  "", "text", "true", "1.0", "../outside", "/absolute/path", "C:\\outside", "<script>alert(1)</script>",
  "*".repeat(256), "RR_FUZZ_SECRET_SHOULD_NOT_SURVIVE", "line one\nline two", "\0",
];

function pick(values) { return values[Math.floor(next() * values.length)]; }

function value(depth = 0) {
  if (depth >= 4 || next() < 0.35) return pick([null, true, false, 0, 1, -1, 9.8, undefined, ...strings]);
  if (next() < 0.45) return Array.from({ length: Math.floor(next() * 5) }, () => value(depth + 1));
  const result = Object.create(null);
  for (let index = 0; index < Math.floor(next() * 6); index += 1) result[pick(keys)] = value(depth + 1);
  return result;
}

function jsonValue() {
  const encoded = JSON.stringify(value());
  return encoded === undefined ? null : JSON.parse(encoded);
}

function validateFindings(findings) {
  assert.ok(Array.isArray(findings));
  assert.ok(findings.length <= 10_000);
  for (const finding of findings) {
    assert.match(finding.id, /^rr-[a-f0-9]{12}$/);
    assert.match(finding.fingerprint, /^sha256:[a-f0-9]{64}$/);
    assert.equal(typeof finding.file, "string");
    assert.equal(typeof finding.plain_summary, "string");
    assert.ok(["critical", "high", "medium", "low"].includes(finding.severity));
  }
}

function validateFindingsOrRepositoryBoundary(parse) {
  try {
    validateFindings(parse());
  } catch (error) {
    assert.ok(error instanceof Error);
    assert.match(error.message, /resolves outside the repository/);
  }
}

test("scanner normalizers survive a deterministic hostile JSON corpus", () => {
  for (let iteration = 0; iteration < 1_000; iteration += 1) {
    const input = jsonValue();
    validateFindingsOrRepositoryBoundary(() => parseSemgrep(input, "/repo"));
    assert.ok(Array.isArray(semgrepErrors(input)));
    validateFindingsOrRepositoryBoundary(() => parseGitleaks(input, "/repo", iteration % 2 === 0));
    validateFindingsOrRepositoryBoundary(() => parseCheckov(input, "/repo"));
    validateFindingsOrRepositoryBoundary(() => parseTrivyImage(input, "fixture.invalid/app:latest"));
    validateFindingsOrRepositoryBoundary(() => parseNpmAudit(input));
    validateFindingsOrRepositoryBoundary(() => parsePipAudit(input, "requirements.txt"));
    validateFindingsOrRepositoryBoundary(() => parseOsvScanner(input, "/repo"));
  }

  const secret = "RR_FUZZ_SECRET_SHOULD_NOT_SURVIVE";
  const normalized = parseGitleaks([{ RuleID: "generic", File: "/repo/.env", Secret: secret, Match: secret, Description: "Generic credential" }], "/repo");
  assert.doesNotMatch(JSON.stringify(normalized), new RegExp(secret));
});

test("strict evidence and policy parsers reject or normalize hostile JSON without prototype pollution", () => {
  const parsers = [
    normalizeConfig,
    parseOrganizationPolicy,
    parseApprovalReceipt,
    parseRemediationProposal,
    parseFindingBaseline,
    parseSuppressionFile,
  ];
  for (let iteration = 0; iteration < 1_000; iteration += 1) {
    const input = jsonValue();
    for (const parser of parsers) {
      try {
        const parsed = parser(input);
        assert.equal(typeof parsed, "object");
        assert.notEqual(parsed, null);
      } catch (error) {
        assert.ok(error instanceof Error);
      }
    }
    assert.equal(Object.prototype.polluted, undefined);
  }
});

test("YAML configuration fuzzing stays bounded and cannot mutate object prototypes", () => {
  const yamlKeys = ["failOn", "paths", "scanners", "semgrep", "pathPolicies", "src/**", "__proto__", "constructor", "prototype", "unknown"];
  const yamlValues = ["high", "low", "true", "false", "[]", "\"1.0\"", "value # comment", ""];
  for (let iteration = 0; iteration < 500; iteration += 1) {
    const lines = Array.from({ length: 1 + Math.floor(next() * 40) }, () => {
      const indent = " ".repeat(Math.floor(next() * 4) * 2);
      return `${indent}${pick(yamlKeys)}: ${pick(yamlValues)}`;
    });
    try {
      normalizeConfig(parseSimpleYaml(`${lines.join("\n")}\n`));
    } catch (error) {
      assert.ok(error instanceof Error);
    }
    assert.equal(Object.prototype.polluted, undefined);
  }

  const manyMappings = `${Array.from({ length: 20_000 }, (_, index) => `key${index}:`).join("\n")}\n`;
  const started = Date.now();
  assert.throws(() => normalizeConfig(parseSimpleYaml(manyMappings)), /Unknown RepoRook configuration key/);
  assert.ok(Date.now() - started < 5_000, "large bounded YAML input should parse in linear practical time");
});
