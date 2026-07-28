import { isAbsolute, posix, resolve } from "node:path";
import type { Finding, FindingSuppression, PolicyEvaluation, ScanReport, ScannerStatus, Severity } from "./types.js";

type JsonRecord = Record<string, unknown>;

const severities = new Set<Severity>(["critical", "high", "medium", "low"]);
const coverageStatuses = new Set(["complete", "partial", "failed"]);
const scannerStatuses = new Set(["ok", "skipped", "error"]);
const scannerScopes = new Set(["repository", "changed-files", "external-targets", "not-applicable"]);

function object(value: unknown, label: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as JsonRecord;
}

function exactKeys(value: JsonRecord, required: string[], optional: string[], label: string): void {
  for (const key of required) if (!(key in value)) throw new Error(`${label}.${key} is required`);
  const allowed = new Set([...required, ...optional]);
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length) throw new Error(`${label} contains unknown field${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`);
}

function string(value: unknown, label: string, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && !value.trim())) throw new Error(`${label} must be ${allowEmpty ? "a string" : "a non-empty string"}`);
  return value;
}

function nullableString(value: unknown, label: string): string | null {
  return value === null ? null : string(value, label);
}

function integer(value: unknown, label: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum) throw new Error(`${label} must be an integer of at least ${minimum}`);
  return Number(value);
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function timestamp(value: unknown, label: string): string {
  const result = string(value, label);
  if (!Number.isFinite(Date.parse(result))) throw new Error(`${label} must be an ISO-8601 timestamp`);
  return result;
}

function stringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value.map((item, index) => string(item, `${label}[${index}]`, true));
}

function repositoryPath(value: unknown, label: string): string {
  const path = string(value, label).replaceAll("\\", "/").replace(/^\.\//, "");
  const normalized = posix.normalize(path);
  if (path.includes("\0") || isAbsolute(path) || /^[A-Za-z]:\//.test(path) || normalized === "." || normalized === ".." || normalized.startsWith("../")) {
    throw new Error(`${label} must be a repository-relative path`);
  }
  return normalized;
}

function suppression(value: unknown, label: string): FindingSuppression {
  const input = object(value, label);
  exactKeys(input, ["id", "finding_id", "owner", "reason", "expires_at", "created_at"], [], label);
  const id = string(input.id, `${label}.id`);
  const findingId = string(input.finding_id, `${label}.finding_id`);
  if (!/^rrs-[a-f0-9]{12}$/.test(id) || !/^rr-[a-f0-9]{12}$/.test(findingId)) throw new Error(`${label} contains an invalid ID`);
  return {
    id,
    finding_id: findingId,
    owner: string(input.owner, `${label}.owner`),
    reason: string(input.reason, `${label}.reason`),
    expires_at: timestamp(input.expires_at, `${label}.expires_at`),
    created_at: timestamp(input.created_at, `${label}.created_at`),
  };
}

function finding(value: unknown, label: string): Finding {
  const input = object(value, label);
  exactKeys(input, ["id", "scanner", "rule", "severity", "file", "line", "plain_summary", "description", "remediation_hint", "fingerprint", "references", "metadata"], ["end_line", "column", "verification_fingerprint"], label);
  const id = string(input.id, `${label}.id`);
  const severity = string(input.severity, `${label}.severity`) as Severity;
  const fingerprint = string(input.fingerprint, `${label}.fingerprint`);
  if (!/^rr-[a-f0-9]{12}$/.test(id) || !severities.has(severity) || !/^sha256:[a-f0-9]{64}$/.test(fingerprint)) throw new Error(`${label} contains an invalid identity or severity`);
  const metadataInput = object(input.metadata, `${label}.metadata`);
  exactKeys(metadataInput, ["cwe", "cve", "package", "raw_severity"], ["installed_version", "fixed_versions", "confidence", "tags", "target_kind", "target", "source_commit"], `${label}.metadata`);
  const targetKind = metadataInput.target_kind;
  if (targetKind !== undefined && targetKind !== "container-image" && targetKind !== "git-history") throw new Error(`${label}.metadata.target_kind is invalid`);
  const file = targetKind === "container-image" ? string(input.file, `${label}.file`) : repositoryPath(input.file, `${label}.file`);
  const verificationFingerprint = input.verification_fingerprint === undefined ? undefined : string(input.verification_fingerprint, `${label}.verification_fingerprint`);
  if (verificationFingerprint !== undefined && !/^sha256:[a-f0-9]{64}$/.test(verificationFingerprint)) throw new Error(`${label}.verification_fingerprint is invalid`);
  const packageName = metadataInput.package === null ? null : string(metadataInput.package, `${label}.metadata.package`);
  const rawSeverity = metadataInput.raw_severity === null ? null : string(metadataInput.raw_severity, `${label}.metadata.raw_severity`, true);
  const metadata: Finding["metadata"] = {
    cwe: stringArray(metadataInput.cwe, `${label}.metadata.cwe`),
    cve: stringArray(metadataInput.cve, `${label}.metadata.cve`),
    package: packageName,
    raw_severity: rawSeverity,
  };
  if (metadataInput.installed_version !== undefined) metadata.installed_version = metadataInput.installed_version === null ? null : string(metadataInput.installed_version, `${label}.metadata.installed_version`, true);
  if (metadataInput.fixed_versions !== undefined) metadata.fixed_versions = stringArray(metadataInput.fixed_versions, `${label}.metadata.fixed_versions`);
  if (metadataInput.confidence !== undefined) metadata.confidence = metadataInput.confidence === null ? null : string(metadataInput.confidence, `${label}.metadata.confidence`, true);
  if (metadataInput.tags !== undefined) metadata.tags = stringArray(metadataInput.tags, `${label}.metadata.tags`);
  if (targetKind !== undefined) metadata.target_kind = targetKind;
  if (metadataInput.target !== undefined) metadata.target = string(metadataInput.target, `${label}.metadata.target`);
  if (metadataInput.source_commit !== undefined) {
    const commit = string(metadataInput.source_commit, `${label}.metadata.source_commit`);
    if (!/^[a-fA-F0-9]{7,64}$/.test(commit)) throw new Error(`${label}.metadata.source_commit is invalid`);
    metadata.source_commit = commit;
  }
  return {
    id,
    scanner: string(input.scanner, `${label}.scanner`),
    rule: string(input.rule, `${label}.rule`),
    severity,
    file,
    line: integer(input.line, `${label}.line`, 1),
    ...(input.end_line === undefined ? {} : { end_line: integer(input.end_line, `${label}.end_line`, 1) }),
    ...(input.column === undefined ? {} : { column: integer(input.column, `${label}.column`, 1) }),
    plain_summary: string(input.plain_summary, `${label}.plain_summary`),
    description: string(input.description, `${label}.description`, true),
    remediation_hint: string(input.remediation_hint, `${label}.remediation_hint`, true),
    fingerprint,
    ...(verificationFingerprint ? { verification_fingerprint: verificationFingerprint } : {}),
    references: stringArray(input.references, `${label}.references`),
    metadata,
  };
}

function scanner(value: unknown, label: string): ScannerStatus {
  const input = object(value, label);
  exactKeys(input, ["name", "applicable", "available", "version", "status", "finding_count", "duration_ms"], ["reason"], label);
  const status = string(input.status, `${label}.status`) as ScannerStatus["status"];
  if (!scannerStatuses.has(status)) throw new Error(`${label}.status is invalid`);
  return {
    name: string(input.name, `${label}.name`),
    applicable: boolean(input.applicable, `${label}.applicable`),
    available: boolean(input.available, `${label}.available`),
    version: input.version === null ? null : string(input.version, `${label}.version`),
    status,
    finding_count: integer(input.finding_count, `${label}.finding_count`),
    duration_ms: integer(input.duration_ms, `${label}.duration_ms`),
    ...(input.reason === undefined ? {} : { reason: string(input.reason, `${label}.reason`, true) }),
  };
}

function policy(value: unknown, findingIds: Set<string>): PolicyEvaluation {
  const input = object(value, "Findings report.policy");
  exactKeys(input, ["evaluated_at", "policy_hash", "baseline", "suppressions", "path_policies", "summary", "findings"], ["organization_policy"], "Findings report.policy");
  const hash = string(input.policy_hash, "Findings report.policy.policy_hash");
  if (!/^sha256:[a-f0-9]{64}$/.test(hash)) throw new Error("Findings report.policy.policy_hash is invalid");
  const baseline = object(input.baseline, "Findings report.policy.baseline");
  exactKeys(baseline, ["configured", "path", "source_commit", "finding_count"], [], "Findings report.policy.baseline");
  const suppressions = object(input.suppressions, "Findings report.policy.suppressions");
  exactKeys(suppressions, ["configured", "path", "active", "expired"], [], "Findings report.policy.suppressions");
  const pathPoliciesInput = object(input.path_policies, "Findings report.policy.path_policies");
  const pathPolicies: Record<string, Severity> = {};
  for (const [path, level] of Object.entries(pathPoliciesInput)) {
    const severity = string(level, `Findings report.policy.path_policies.${path}`) as Severity;
    if (!severities.has(severity)) throw new Error(`Findings report.policy.path_policies.${path} is invalid`);
    pathPolicies[path] = severity;
  }
  const summaryInput = object(input.summary, "Findings report.policy.summary");
  const summaryKeys = ["new", "existing", "actionable", "below_threshold", "suppressed", "expired_suppressions"];
  exactKeys(summaryInput, summaryKeys, [], "Findings report.policy.summary");
  if (!Array.isArray(input.findings)) throw new Error("Findings report.policy.findings must be an array");
  const policyFindings = input.findings.map((entry, index) => {
    const label = `Findings report.policy.findings[${index}]`;
    const item = object(entry, label);
    exactKeys(item, ["finding_id", "baseline", "disposition", "effective_fail_on", "matched_path_policy", "suppression", "expired_suppression"], [], label);
    const findingId = string(item.finding_id, `${label}.finding_id`);
    if (!findingIds.has(findingId)) throw new Error(`${label}.finding_id does not reference a report finding`);
    const baselineValue = string(item.baseline, `${label}.baseline`) as "new" | "existing" | "not-configured";
    const disposition = string(item.disposition, `${label}.disposition`) as "actionable" | "baseline" | "suppressed" | "below-threshold";
    const effectiveFailOn = string(item.effective_fail_on, `${label}.effective_fail_on`) as Severity;
    if (!["new", "existing", "not-configured"].includes(baselineValue) || !["actionable", "baseline", "suppressed", "below-threshold"].includes(disposition) || !severities.has(effectiveFailOn)) throw new Error(`${label} contains an invalid policy disposition`);
    return {
      finding_id: findingId,
      baseline: baselineValue,
      disposition,
      effective_fail_on: effectiveFailOn,
      matched_path_policy: item.matched_path_policy === null ? null : string(item.matched_path_policy, `${label}.matched_path_policy`),
      suppression: item.suppression === null ? null : suppression(item.suppression, `${label}.suppression`),
      expired_suppression: item.expired_suppression === null ? null : suppression(item.expired_suppression, `${label}.expired_suppression`),
    };
  });
  let organizationPolicy: PolicyEvaluation["organization_policy"];
  if (input.organization_policy !== undefined) {
    const organization = object(input.organization_policy, "Findings report.policy.organization_policy");
    exactKeys(organization, ["name", "path", "hash"], [], "Findings report.policy.organization_policy");
    const organizationHash = string(organization.hash, "Findings report.policy.organization_policy.hash");
    if (!/^sha256:[a-f0-9]{64}$/.test(organizationHash)) throw new Error("Findings report.policy.organization_policy.hash is invalid");
    organizationPolicy = { name: string(organization.name, "Findings report.policy.organization_policy.name"), path: string(organization.path, "Findings report.policy.organization_policy.path"), hash: organizationHash };
  }
  return {
    evaluated_at: timestamp(input.evaluated_at, "Findings report.policy.evaluated_at"),
    policy_hash: hash,
    baseline: { configured: boolean(baseline.configured, "Findings report.policy.baseline.configured"), path: string(baseline.path, "Findings report.policy.baseline.path", true), source_commit: nullableString(baseline.source_commit, "Findings report.policy.baseline.source_commit"), finding_count: integer(baseline.finding_count, "Findings report.policy.baseline.finding_count") },
    suppressions: { configured: boolean(suppressions.configured, "Findings report.policy.suppressions.configured"), path: string(suppressions.path, "Findings report.policy.suppressions.path", true), active: integer(suppressions.active, "Findings report.policy.suppressions.active"), expired: integer(suppressions.expired, "Findings report.policy.suppressions.expired") },
    path_policies: pathPolicies,
    ...(organizationPolicy ? { organization_policy: organizationPolicy } : {}),
    summary: Object.fromEntries(summaryKeys.map((key) => [key, integer(summaryInput[key], `Findings report.policy.summary.${key}`)])) as PolicyEvaluation["summary"],
    findings: policyFindings,
  };
}

export function parseFindingsReport(value: unknown): ScanReport {
  const input = object(value, "Findings report");
  exactKeys(input, ["schema_version", "tool", "target", "generated_at", "coverage_status", "summary", "scanners", "findings", "scan_receipt"], ["policy"], "Findings report");
  if (input.schema_version !== "1.0") throw new Error("Findings report.schema_version must be 1.0");
  const tool = object(input.tool, "Findings report.tool");
  exactKeys(tool, ["name", "version"], [], "Findings report.tool");
  if (tool.name !== "reporook") throw new Error("Findings report.tool.name must be reporook");
  const target = object(input.target, "Findings report.target");
  exactKeys(target, ["path", "commit"], [], "Findings report.target");
  const coverageStatus = string(input.coverage_status, "Findings report.coverage_status") as ScanReport["coverage_status"];
  if (!coverageStatuses.has(coverageStatus)) throw new Error("Findings report.coverage_status is invalid");
  if (!Array.isArray(input.findings) || !Array.isArray(input.scanners)) throw new Error("Findings report findings and scanners must be arrays");
  const parsedFindings = input.findings.map((item, index) => finding(item, `Findings report.findings[${index}]`));
  const parsedScanners = input.scanners.map((item, index) => scanner(item, `Findings report.scanners[${index}]`));
  const findingIds = new Set(parsedFindings.map((item) => item.id));
  if (findingIds.size !== parsedFindings.length) throw new Error("Findings report finding IDs must be unique");
  const summaryInput = object(input.summary, "Findings report.summary");
  const summaryKeys = ["critical", "high", "medium", "low", "total"];
  exactKeys(summaryInput, summaryKeys, [], "Findings report.summary");
  const summary = Object.fromEntries(summaryKeys.map((key) => [key, integer(summaryInput[key], `Findings report.summary.${key}`)])) as ScanReport["summary"];
  const receiptInput = object(input.scan_receipt, "Findings report.scan_receipt");
  exactKeys(receiptInput, ["target", "commit", "config_hash", "scanner_versions", "started_at", "completed_at"], ["changed_files", "scanner_scopes"], "Findings report.scan_receipt");
  const versionsInput = object(receiptInput.scanner_versions, "Findings report.scan_receipt.scanner_versions");
  const scannerVersions = Object.fromEntries(Object.entries(versionsInput).map(([name, version]) => [string(name, "Scanner version name"), version === null ? null : string(version, `Findings report.scan_receipt.scanner_versions.${name}`)]));
  const scannerScopeInput = receiptInput.scanner_scopes === undefined ? undefined : object(receiptInput.scanner_scopes, "Findings report.scan_receipt.scanner_scopes");
  const parsedScopes = scannerScopeInput === undefined ? undefined : Object.fromEntries(Object.entries(scannerScopeInput).map(([name, scope]) => {
    const parsed = string(scope, `Findings report.scan_receipt.scanner_scopes.${name}`);
    if (!scannerScopes.has(parsed)) throw new Error(`Findings report.scan_receipt.scanner_scopes.${name} is invalid`);
    return [name, parsed];
  })) as ScanReport["scan_receipt"]["scanner_scopes"];
  const report: ScanReport = {
    schema_version: "1.0",
    tool: { name: "reporook", version: string(tool.version, "Findings report.tool.version") },
    target: { path: string(target.path, "Findings report.target.path"), commit: nullableString(target.commit, "Findings report.target.commit") },
    generated_at: timestamp(input.generated_at, "Findings report.generated_at"),
    coverage_status: coverageStatus,
    summary,
    scanners: parsedScanners,
    findings: parsedFindings,
    ...(input.policy === undefined ? {} : { policy: policy(input.policy, findingIds) }),
    scan_receipt: {
      target: string(receiptInput.target, "Findings report.scan_receipt.target"),
      commit: nullableString(receiptInput.commit, "Findings report.scan_receipt.commit"),
      config_hash: string(receiptInput.config_hash, "Findings report.scan_receipt.config_hash"),
      scanner_versions: scannerVersions,
      started_at: timestamp(receiptInput.started_at, "Findings report.scan_receipt.started_at"),
      completed_at: timestamp(receiptInput.completed_at, "Findings report.scan_receipt.completed_at"),
      ...(receiptInput.changed_files === undefined ? {} : { changed_files: stringArray(receiptInput.changed_files, "Findings report.scan_receipt.changed_files").map((path, index) => repositoryPath(path, `Findings report.scan_receipt.changed_files[${index}]`)) }),
      ...(parsedScopes === undefined ? {} : { scanner_scopes: parsedScopes }),
    },
  };
  assertFindingsReportConsistency(report);
  return report;
}

export function assertFindingsReportConsistency(report: ScanReport, options: { expectedTarget?: string } = {}): void {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of report.findings) counts[item.severity] += 1;
  if (report.summary.total !== report.findings.length || Object.entries(counts).some(([severity, count]) => report.summary[severity as Severity] !== count)) {
    throw new Error("Findings report summary does not match its findings");
  }
  const scannerNames = report.scanners.map((item) => item.name);
  if (new Set(scannerNames).size !== scannerNames.length) throw new Error("Findings report scanner names must be unique");
  for (const scanner of report.scanners) {
    const count = report.findings.filter((item) => item.scanner === scanner.name).length;
    if (scanner.finding_count !== count) throw new Error(`Findings report scanner ${scanner.name} finding_count does not match its findings`);
  }
  const applicable = report.scanners.filter((item) => item.applicable);
  const completed = applicable.filter((item) => item.status === "ok");
  const expectedCoverage = !applicable.length ? "failed" : completed.length === applicable.length ? "complete" : completed.length ? "partial" : "failed";
  if (report.coverage_status !== expectedCoverage) throw new Error(`Findings report coverage_status must be ${expectedCoverage} for its scanner states`);
  if (report.target.path !== report.scan_receipt.target || report.target.commit !== report.scan_receipt.commit) throw new Error("Findings report target and scan receipt do not agree");
  if (!/^sha256:[a-f0-9]{64}$/.test(report.scan_receipt.config_hash)) throw new Error("Findings report scan receipt config_hash is invalid");
  const receiptScannerNames = Object.keys(report.scan_receipt.scanner_versions).sort();
  if (JSON.stringify(receiptScannerNames) !== JSON.stringify([...scannerNames].sort())) throw new Error("Findings report scan receipt scanner_versions do not match its scanners");
  for (const scanner of report.scanners) if (report.scan_receipt.scanner_versions[scanner.name] !== scanner.version) throw new Error(`Findings report scanner version disagrees for ${scanner.name}`);
  if (report.scan_receipt.scanner_scopes) {
    if (JSON.stringify(Object.keys(report.scan_receipt.scanner_scopes).sort()) !== JSON.stringify([...scannerNames].sort())) throw new Error("Findings report scan receipt scanner_scopes do not match its scanners");
  }
  if (options.expectedTarget && resolve(report.target.path) !== resolve(options.expectedTarget)) throw new Error("Findings report is bound to a different repository target");
}
