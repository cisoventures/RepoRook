import { stat } from "node:fs/promises";
import { resolve } from "node:path";
import { cacheEligible, readScannerCache, scannerCacheKey, writeScannerCache } from "./cache.js";
import { sha256 } from "./fingerprint.js";
import { gitChangedFiles, gitCommit } from "./git.js";
import { inConfiguredScope } from "./incremental.js";
import { evaluatePolicy } from "./policy.js";
import { meetsThreshold, sortBySeverity } from "./severity.js";
import { GitleaksScanner } from "./scanners/gitleaks.js";
import { CheckovScanner } from "./scanners/checkov.js";
import { NpmAuditScanner } from "./scanners/npm-audit.js";
import { OsvScanner } from "./scanners/osv-scanner.js";
import { PipAuditScanner } from "./scanners/pip-audit.js";
import { SemgrepScanner } from "./scanners/semgrep.js";
import { TrivyImageScanner } from "./scanners/trivy-image.js";
import { status } from "./scanners/shared.js";
import type { Finding, ScanOptions, ScanReport, ScannerAdapter, ScannerContext, ScannerResult, ScannerScope, ScannerStatus, Severity } from "./types.js";
import { VERSION } from "./version.js";

export { VERSION };

export const defaultScanners = (): ScannerAdapter[] => [
  new SemgrepScanner(),
  new GitleaksScanner(),
  new NpmAuditScanner(),
  new PipAuditScanner(),
  new OsvScanner(),
  new CheckovScanner(),
  new TrivyImageScanner(),
];

function summary(findings: Finding[]): Record<Severity | "total", number> {
  const counts: Record<Severity | "total", number> = { critical: 0, high: 0, medium: 0, low: 0, total: findings.length };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

function deduplicate(findings: Finding[]): Finding[] {
  const byFingerprint = new Map<string, Finding>();
  for (const finding of findings) {
    const existing = byFingerprint.get(finding.fingerprint);
    if (!existing) byFingerprint.set(finding.fingerprint, finding);
  }
  return sortBySeverity([...byFingerprint.values()]);
}

function coverage(statuses: ScannerStatus[]): "complete" | "partial" | "failed" {
  const applicable = statuses.filter((scanner) => scanner.applicable);
  if (!applicable.length) return "failed";
  const completed = applicable.filter((scanner) => scanner.status === "ok").length;
  if (completed === applicable.length) return "complete";
  return completed > 0 ? "partial" : "failed";
}

function filterFindings(findings: Finding[], config: ScanOptions["config"], changed_files?: string[]): Finding[] {
  return findings.filter((finding) => {
    if (finding.metadata.target_kind) return true;
    if (!inConfiguredScope(finding.file, config)) return false;
    if (changed_files && !changed_files.includes(finding.file)) return false;
    return true;
  });
}

export async function scanRepository(options: ScanOptions, scanners: ScannerAdapter[] = defaultScanners()): Promise<ScanReport> {
  const started_at = new Date().toISOString();
  const target = resolve(options.target);
  const targetStats = await stat(target).catch(() => null);
  if (!targetStats?.isDirectory()) throw new Error(`Target is not a directory: ${target}`);
  const commit = await gitCommit(target);
  const changed_files = options.changedBase !== undefined ? await gitChangedFiles(target, options.changedBase || undefined, options.changedHead) : undefined;
  const useCache = options.cacheEnabled ?? options.config.cacheEnabled;
  const canCache = useCache && await cacheEligible(target, commit, options.config);
  const cacheTtlMs = options.cacheTtlMs ?? options.config.cacheTtlMinutes * 60_000;

  const runs = await Promise.all(scanners.map(async (scanner) => {
    if (options.config.scanners[scanner.name] === false) {
      return { status: status(scanner.name, { applicable: false, available: false, status: "skipped", reason: "disabled by configuration" }), findings: [], scope: "not-applicable" as ScannerScope };
    }
    let context: ScannerContext = { target, config: options.config, ...(changed_files !== undefined ? { changedFiles: changed_files } : {}) };
    let scannerScope: ScannerScope = "repository";
    let incrementalConfirmed = false;
    if (changed_files !== undefined && scanner.incremental) {
      try {
        const incremental = await scanner.incremental(context);
        if (!incremental.applicable) {
          return {
            status: status(scanner.name, { applicable: false, available: false, status: "skipped", reason: incremental.reason ?? "no changed files in scanner scope" }),
            findings: [],
            scope: "not-applicable" as ScannerScope,
          };
        }
        scannerScope = incremental.scope;
        if (incremental.scanFiles) {
          context = { ...context, scanFiles: incremental.scanFiles };
          incrementalConfirmed = incremental.scanFiles.length > 0;
        }
      } catch (error) {
        const reason = (error instanceof Error ? error.message : String(error)).replace(/\s+/g, " ").slice(0, 500);
        return {
          status: status(scanner.name, { applicable: true, available: false, status: "error", reason: `incremental scan planning failed: ${reason}` }),
          findings: [],
          scope: scannerScope,
        };
      }
    }
    let applicability: { applicable: boolean; reason?: string };
    try {
      applicability = incrementalConfirmed ? { applicable: true } : await scanner.isApplicable(target, options.config);
    } catch (error) {
      const reason = (error instanceof Error ? error.message : String(error)).replace(/\s+/g, " ").slice(0, 500);
      return {
        status: status(scanner.name, { applicable: true, available: false, status: "error", reason: `applicability discovery failed: ${reason}` }),
        findings: [],
        scope: scannerScope,
      };
    }
    if (!applicability.applicable) {
      return { status: status(scanner.name, { applicable: false, available: false, status: "skipped", reason: applicability.reason ?? "not applicable" }), findings: [], scope: "not-applicable" as ScannerScope };
    }
    const scannerVersion = canCache && scanner.version
      ? await scanner.version(context).catch(() => undefined)
      : undefined;
    const key = canCache && commit && scannerVersion
      ? scannerCacheKey({ commit, scanner: scanner.name, scannerVersion, config: options.config, ...(changed_files ? { changedFiles: changed_files } : {}) })
      : null;
    if (key && scannerVersion && !options.refreshCache) {
      const cached = await readScannerCache({ target, scanner: scanner.name, version: scannerVersion, key, ttlMs: cacheTtlMs }).catch(() => null);
      if (cached) return { ...cached, scope: scannerScope };
    }
    const execute = async (): Promise<ScannerResult> => {
      try {
        return await scanner.run({ ...context, ...(scannerVersion !== undefined ? { scannerVersion } : {}) });
      } catch (error) {
        const reason = (error instanceof Error ? error.message : String(error)).replace(/\s+/g, " ").slice(0, 500);
        return { status: status(scanner.name, { applicable: true, available: scannerVersion !== null, version: scannerVersion ?? null, status: "error", reason }), findings: [] };
      }
    };
    let run = await execute();
    let attempts = 1;
    let duration = run.status.duration_ms;
    while (run.status.status === "error" && attempts <= options.config.scannerRetries) {
      run = await execute();
      duration += run.status.duration_ms;
      attempts += 1;
    }
    run.status.duration_ms = duration;
    if (attempts > 1) {
      const retries = attempts - 1;
      const retrySummary = run.status.status === "ok"
        ? `completed after ${retries} ${retries === 1 ? "retry" : "retries"}`
        : `failed after ${attempts} attempts`;
      run.status.reason = `${run.status.reason ? `${run.status.reason}; ` : ""}${retrySummary}`;
    }
    if (key && scannerVersion && run.status.status === "ok") {
      await writeScannerCache({ target, scanner: scanner.name, version: scannerVersion, key, result: run }).catch(() => undefined);
    }
    return { ...run, scope: scannerScope };
  }));

  const statuses = runs.map((run) => run.status);
  const required = new Set([...options.config.requiredScanners, ...(options.requireScanners ? statuses.filter((item) => item.applicable).map((item) => item.name) : [])]);
  for (const scanner of statuses) {
    if (required.has(scanner.name) && scanner.applicable && scanner.status !== "ok") {
      scanner.reason = `${scanner.reason ?? "scanner did not complete"}; scanner is required`;
    }
  }
  const findings = deduplicate(filterFindings(runs.flatMap((run) => run.findings), options.config, changed_files));
  const policy = await evaluatePolicy(target, findings, options.config);
  const completed_at = new Date().toISOString();
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: VERSION },
    target: { path: target, commit },
    generated_at: completed_at,
    coverage_status: coverage(statuses),
    summary: summary(findings),
    scanners: statuses,
    findings,
    policy,
    scan_receipt: {
      target,
      commit,
      config_hash: `sha256:${sha256(JSON.stringify({ config: options.config, policy_hash: policy.policy_hash }))}`,
      scanner_versions: Object.fromEntries(statuses.map((scanner) => [scanner.name, scanner.version])),
      started_at,
      completed_at,
      ...(changed_files ? { changed_files } : {}),
      ...(changed_files !== undefined ? { scanner_scopes: Object.fromEntries(runs.map((run) => [run.status.name, run.scope])) } : {}),
    },
  };
}

export function requiredScannerFailure(report: ScanReport, requiredScanners: string[], requireAllApplicable: boolean): boolean {
  const required = new Set(requiredScanners);
  return report.scanners.some((scanner) =>
    scanner.applicable && scanner.status !== "ok" && (requireAllApplicable || required.has(scanner.name)),
  );
}

export function scanExitCode(
  report: ScanReport,
  failOn: Severity,
  requiredScanners: string[],
  requireAllApplicable: boolean,
  allowNoCoverage: boolean,
): 0 | 1 | 2 {
  if (!allowNoCoverage && report.coverage_status !== "complete") return 2;
  if (requiredScannerFailure(report, requiredScanners, requireAllApplicable)) return 2;
  if (report.policy) return report.policy.summary.actionable > 0 ? 1 : 0;
  return report.findings.some((finding) => meetsThreshold(finding.severity, failOn)) ? 1 : 0;
}
