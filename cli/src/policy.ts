import { existsSync } from "node:fs";
import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { sha256 } from "./fingerprint.js";
import { matchesAny } from "./path-utils.js";
import { meetsThreshold } from "./severity.js";
import type {
  Finding,
  FindingBaseline,
  FindingPolicyResult,
  FindingSuppression,
  PolicyEvaluation,
  RepoRookConfig,
  ScanReport,
  Severity,
  SuppressionFile,
} from "./types.js";
import { VERSION } from "./version.js";

const severityRank: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const baselineKeys = new Set(["schema_version", "tool", "created_at", "source", "findings"]);
const baselineToolKeys = new Set(["name", "version"]);
const baselineSourceKeys = new Set(["commit", "config_hash", "generated_at"]);
const baselineFindingKeys = new Set(["finding_id", "fingerprint", "scanner", "rule", "severity", "file"]);
const suppressionFileKeys = new Set(["schema_version", "suppressions"]);
const suppressionKeys = new Set(["id", "finding_id", "owner", "reason", "expires_at", "created_at"]);

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, allowed: Set<string>, label: string): void {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length) throw new Error(`${label} contains unknown field${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`);
}

function nonEmpty(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} must be a non-empty string`);
  return value.trim();
}

function isoDate(value: unknown, label: string): string {
  const text = nonEmpty(value, label);
  const timestamp = Date.parse(text);
  if (!Number.isFinite(timestamp)) throw new Error(`${label} must be an ISO-8601 timestamp`);
  return new Date(timestamp).toISOString();
}

async function safePolicyPath(target: string, requested: string): Promise<{ path: string; exists: boolean }> {
  if (!requested.trim()) throw new Error("Policy file path must be non-empty");
  if (isAbsolute(requested)) throw new Error("Policy file path must be repository-relative");
  const selected = await realpath(resolve(target));
  let root = selected;
  while (!existsSync(join(root, ".git")) && resolve(root, "..") !== root) root = resolve(root, "..");
  if (!existsSync(join(root, ".git"))) root = selected;
  const path = resolve(selected, requested);
  const traversal = relative(root, path);
  if (traversal === ".." || traversal.startsWith(`..${sep}`) || isAbsolute(traversal)) {
    throw new Error("Policy file path resolves outside the repository");
  }
  let current = root;
  for (const segment of traversal.split(sep).filter(Boolean)) {
    current = join(current, segment);
    try {
      if ((await lstat(current)).isSymbolicLink()) throw new Error(`Policy file path contains a symbolic link: ${current}`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { path, exists: false };
      throw error;
    }
  }
  return { path, exists: true };
}

async function optionalJson(target: string, requested: string, label: string): Promise<{ path: string; value: unknown | null }> {
  const selected = await safePolicyPath(target, requested);
  if (!selected.exists) return { path: requested, value: null };
  try {
    return { path: requested, value: JSON.parse(await readFile(selected.path, "utf8")) as unknown };
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} is not valid JSON: ${error.message}`);
    throw error;
  }
}

export function parseFindingBaseline(value: unknown): FindingBaseline {
  const input = record(value, "Baseline");
  exactKeys(input, baselineKeys, "Baseline");
  if (input.schema_version !== "1.0") throw new Error("Baseline schema_version must be 1.0");
  const tool = record(input.tool, "Baseline tool");
  exactKeys(tool, baselineToolKeys, "Baseline tool");
  if (tool.name !== "reporook") throw new Error("Baseline tool.name must be reporook");
  const toolVersion = nonEmpty(tool.version, "Baseline tool.version");
  const source = record(input.source, "Baseline source");
  exactKeys(source, baselineSourceKeys, "Baseline source");
  const commit = source.commit === null ? null : nonEmpty(source.commit, "Baseline source.commit");
  const configHash = nonEmpty(source.config_hash, "Baseline source.config_hash");
  const generatedAt = isoDate(source.generated_at, "Baseline source.generated_at");
  const createdAt = isoDate(input.created_at, "Baseline created_at");
  if (!Array.isArray(input.findings)) throw new Error("Baseline findings must be an array");
  const findings = input.findings.map((entry, index) => {
    const item = record(entry, `Baseline finding ${index + 1}`);
    exactKeys(item, baselineFindingKeys, `Baseline finding ${index + 1}`);
    const findingId = nonEmpty(item.finding_id, `Baseline finding ${index + 1}.finding_id`);
    if (!/^rr-[a-f0-9]{12}$/.test(findingId)) throw new Error(`Baseline finding ${index + 1}.finding_id is invalid`);
    const fingerprint = nonEmpty(item.fingerprint, `Baseline finding ${index + 1}.fingerprint`);
    if (!/^sha256:[a-f0-9]{64}$/.test(fingerprint)) throw new Error(`Baseline finding ${index + 1}.fingerprint is invalid`);
    const severity = nonEmpty(item.severity, `Baseline finding ${index + 1}.severity`) as Severity;
    if (!Object.hasOwn(severityRank, severity)) throw new Error(`Baseline finding ${index + 1}.severity is invalid`);
    return {
      finding_id: findingId,
      fingerprint,
      scanner: nonEmpty(item.scanner, `Baseline finding ${index + 1}.scanner`),
      rule: nonEmpty(item.rule, `Baseline finding ${index + 1}.rule`),
      severity,
      file: nonEmpty(item.file, `Baseline finding ${index + 1}.file`),
    };
  }).sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
  if (new Set(findings.map((finding) => finding.fingerprint)).size !== findings.length) {
    throw new Error("Baseline findings contain duplicate fingerprints");
  }
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: toolVersion },
    created_at: createdAt,
    source: {
      commit,
      config_hash: configHash,
      generated_at: generatedAt,
    },
    findings,
  };
}

function parseSuppression(value: unknown, index: number): FindingSuppression {
  const label = `Suppression ${index + 1}`;
  const input = record(value, label);
  exactKeys(input, suppressionKeys, label);
  const id = nonEmpty(input.id, `${label}.id`);
  if (!/^rrs-[a-f0-9]{12}$/.test(id)) throw new Error(`${label}.id must look like rrs-0123456789ab`);
  const findingId = nonEmpty(input.finding_id, `${label}.finding_id`);
  if (!/^rr-[a-f0-9]{12}$/.test(findingId)) throw new Error(`${label}.finding_id is invalid`);
  return {
    id,
    finding_id: findingId,
    owner: nonEmpty(input.owner, `${label}.owner`),
    reason: nonEmpty(input.reason, `${label}.reason`),
    expires_at: isoDate(input.expires_at, `${label}.expires_at`),
    created_at: isoDate(input.created_at, `${label}.created_at`),
  };
}

export function parseSuppressionFile(value: unknown): SuppressionFile {
  const input = record(value, "Suppression file");
  exactKeys(input, suppressionFileKeys, "Suppression file");
  if (input.schema_version !== "1.0") throw new Error("Suppression file schema_version must be 1.0");
  if (!Array.isArray(input.suppressions)) throw new Error("Suppression file suppressions must be an array");
  const suppressions = input.suppressions.map(parseSuppression).sort((left, right) => left.id.localeCompare(right.id));
  if (new Set(suppressions.map((item) => item.id)).size !== suppressions.length) throw new Error("Suppression IDs must be unique");
  if (new Set(suppressions.map((item) => item.finding_id)).size !== suppressions.length) throw new Error("Only one suppression may target a finding");
  return { schema_version: "1.0", suppressions };
}

export function createFindingBaseline(report: ScanReport, now = new Date()): FindingBaseline {
  if (report.coverage_status !== "complete") {
    throw new Error("Refusing to create a baseline from incomplete scanner coverage");
  }
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: VERSION },
    created_at: now.toISOString(),
    source: {
      commit: report.scan_receipt.commit,
      config_hash: report.scan_receipt.config_hash,
      generated_at: report.generated_at,
    },
    findings: report.findings.map((finding) => ({
      finding_id: finding.id,
      fingerprint: finding.fingerprint,
      scanner: finding.scanner,
      rule: finding.rule,
      severity: finding.severity,
      file: finding.file,
    })).sort((left, right) => left.fingerprint.localeCompare(right.fingerprint)),
  };
}

function expiry(value: string): string {
  const normalized = /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T23:59:59.999Z` : value;
  return isoDate(normalized, "expires");
}

export function createFindingSuppression(
  report: ScanReport,
  findingId: string,
  owner: string,
  reason: string,
  expires: string,
  now = new Date(),
): FindingSuppression {
  const finding = report.findings.find((candidate) => candidate.id === findingId);
  if (!finding) throw new Error(`Finding not found: ${findingId}`);
  const normalizedOwner = nonEmpty(owner, "owner");
  const normalizedReason = nonEmpty(reason, "reason");
  const expiresAt = expiry(nonEmpty(expires, "expires"));
  if (Date.parse(expiresAt) <= now.getTime()) throw new Error("Suppression expiry must be in the future");
  const identity = [finding.id, finding.fingerprint, normalizedOwner, normalizedReason, expiresAt].join("\0");
  return {
    id: `rrs-${sha256(identity).slice(0, 12)}`,
    finding_id: finding.id,
    owner: normalizedOwner,
    reason: normalizedReason,
    expires_at: expiresAt,
    created_at: now.toISOString(),
  };
}

function strictestPathPolicy(finding: Finding, config: RepoRookConfig): { threshold: Severity; pattern: string | null } {
  let threshold = config.failOn;
  let pattern: string | null = null;
  for (const [candidate, candidateThreshold] of Object.entries(config.pathPolicies)) {
    if (!matchesAny(finding.file, [candidate])) continue;
    if (severityRank[candidateThreshold] < severityRank[threshold]) {
      threshold = candidateThreshold;
      pattern = candidate;
    } else if (severityRank[candidateThreshold] === severityRank[threshold] && pattern === null) {
      pattern = candidate;
    }
  }
  return { threshold, pattern };
}

export async function evaluatePolicy(
  target: string,
  findings: Finding[],
  config: RepoRookConfig,
  now = new Date(),
): Promise<PolicyEvaluation> {
  const baselineInput = await optionalJson(target, config.baselineFile, "Baseline file");
  const suppressionInput = await optionalJson(target, config.suppressionsFile, "Suppression file");
  const baseline = baselineInput.value === null ? null : parseFindingBaseline(baselineInput.value);
  const suppressionFile = suppressionInput.value === null ? null : parseSuppressionFile(suppressionInput.value);
  const baselineFingerprints = new Set(baseline?.findings.map((finding) => finding.fingerprint) ?? []);
  const suppressionsByFinding = new Map((suppressionFile?.suppressions ?? []).map((item) => [item.finding_id, item]));
  const evaluatedAt = now.toISOString();
  const results: FindingPolicyResult[] = findings.map((finding) => {
    const suppression = suppressionsByFinding.get(finding.id) ?? null;
    const activeSuppression = suppression && Date.parse(suppression.expires_at) > now.getTime() ? suppression : null;
    const expiredSuppression = suppression && !activeSuppression ? suppression : null;
    const baselineDisposition = baseline === null ? "not-configured" : baselineFingerprints.has(finding.fingerprint) ? "existing" : "new";
    const pathPolicy = strictestPathPolicy(finding, config);
    const disposition = activeSuppression
      ? "suppressed"
      : baselineDisposition === "existing"
        ? "baseline"
        : meetsThreshold(finding.severity, pathPolicy.threshold)
          ? "actionable"
          : "below-threshold";
    return {
      finding_id: finding.id,
      baseline: baselineDisposition,
      disposition,
      effective_fail_on: pathPolicy.threshold,
      matched_path_policy: pathPolicy.pattern,
      suppression: activeSuppression,
      expired_suppression: expiredSuppression,
    };
  });
  const active = (suppressionFile?.suppressions ?? []).filter((item) => Date.parse(item.expires_at) > now.getTime()).length;
  const expired = (suppressionFile?.suppressions.length ?? 0) - active;
  const canonicalPolicy = {
    baseline,
    suppressions: suppressionFile,
    path_policies: config.pathPolicies,
  };
  return {
    evaluated_at: evaluatedAt,
    policy_hash: `sha256:${sha256(JSON.stringify(canonicalPolicy))}`,
    baseline: {
      configured: baseline !== null,
      path: baselineInput.path,
      source_commit: baseline?.source.commit ?? null,
      finding_count: baseline?.findings.length ?? 0,
    },
    suppressions: {
      configured: suppressionFile !== null,
      path: suppressionInput.path,
      active,
      expired,
    },
    path_policies: { ...config.pathPolicies },
    summary: {
      new: results.filter((item) => item.baseline === "new").length,
      existing: results.filter((item) => item.baseline === "existing").length,
      actionable: results.filter((item) => item.disposition === "actionable").length,
      below_threshold: results.filter((item) => item.disposition === "below-threshold").length,
      suppressed: results.filter((item) => item.disposition === "suppressed").length,
      expired_suppressions: results.filter((item) => item.expired_suppression !== null).length,
    },
    findings: results,
  };
}

export async function readSuppressionFile(target: string, requested: string): Promise<SuppressionFile> {
  const input = await optionalJson(target, requested, "Suppression file");
  return input.value === null ? { schema_version: "1.0", suppressions: [] } : parseSuppressionFile(input.value);
}
