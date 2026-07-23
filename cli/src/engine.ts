import { stat } from "node:fs/promises";
import { resolve } from "node:path";
import { sha256 } from "./fingerprint.js";
import { gitChangedFiles, gitCommit } from "./git.js";
import { matchesAny } from "./path-utils.js";
import { meetsThreshold, sortBySeverity } from "./severity.js";
import { GitleaksScanner } from "./scanners/gitleaks.js";
import { NpmAuditScanner } from "./scanners/npm-audit.js";
import { PipAuditScanner } from "./scanners/pip-audit.js";
import { SemgrepScanner } from "./scanners/semgrep.js";
import { status } from "./scanners/shared.js";
import type { Finding, ScanOptions, ScanReport, ScannerAdapter, ScannerStatus, Severity } from "./types.js";

export const VERSION = "0.1.0";

export const defaultScanners = (): ScannerAdapter[] => [
  new SemgrepScanner(),
  new GitleaksScanner(),
  new NpmAuditScanner(),
  new PipAuditScanner(),
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

function filterFindings(findings: Finding[], ignore: string[], paths: string[], changed_files?: string[]): Finding[] {
  return findings.filter((finding) => {
    if (matchesAny(finding.file, ignore)) return false;
    if (paths.length && !paths.includes(".") && !matchesAny(finding.file, paths.map((path) => path.endsWith("/**") ? path : `${path.replace(/\/$/, "")}/**`))) return false;
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

  const runs = await Promise.all(scanners.map(async (scanner) => {
    if (options.config.scanners[scanner.name] === false) {
      return { status: status(scanner.name, { applicable: false, available: false, status: "skipped", reason: "disabled by configuration" }), findings: [] };
    }
    const applicability = await scanner.isApplicable(target);
    if (!applicability.applicable) {
      return { status: status(scanner.name, { applicable: false, available: false, status: "skipped", reason: applicability.reason ?? "not applicable" }), findings: [] };
    }
    return await scanner.run({ target, config: options.config });
  }));

  const statuses = runs.map((run) => run.status);
  const required = new Set([...options.config.requiredScanners, ...(options.requireScanners ? statuses.filter((item) => item.applicable).map((item) => item.name) : [])]);
  for (const scanner of statuses) {
    if (required.has(scanner.name) && scanner.applicable && scanner.status !== "ok") {
      scanner.reason = `${scanner.reason ?? "scanner did not complete"}; scanner is required`;
    }
  }
  const findings = deduplicate(filterFindings(runs.flatMap((run) => run.findings), options.config.ignore, options.config.paths, changed_files));
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
    scan_receipt: {
      target,
      commit,
      config_hash: `sha256:${sha256(JSON.stringify(options.config))}`,
      scanner_versions: Object.fromEntries(statuses.map((scanner) => [scanner.name, scanner.version])),
      started_at,
      completed_at,
      ...(changed_files ? { changed_files } : {}),
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
  if (!allowNoCoverage && report.coverage_status === "failed") return 2;
  if (requiredScannerFailure(report, requiredScanners, requireAllApplicable)) return 2;
  return report.findings.some((finding) => meetsThreshold(finding.severity, failOn)) ? 1 : 0;
}
