import { sortBySeverity } from "./severity.js";
import type { Finding, ScanReport, Severity } from "./types.js";

const labels: Record<Severity, string> = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" };

function compact(value: string, limit = 280): string {
  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized.length <= limit ? normalized : `${normalized.slice(0, limit - 1).trimEnd()}…`;
}

export function renderTerminal(report: ScanReport): string {
  const lines: string[] = [];
  lines.push("RepoRook security scan");
  lines.push(`Coverage: ${report.coverage_status.toUpperCase()} | Findings: ${report.summary.total} | Commit: ${report.target.commit?.slice(0, 12) ?? "working tree"}`);
  lines.push("");
  for (const scanner of report.scanners) {
    const mark = scanner.status === "ok" ? "✓" : scanner.applicable ? "!" : "-";
    lines.push(`${mark} ${scanner.name}: ${scanner.status}${scanner.status === "ok" ? ` (${scanner.finding_count} findings)` : scanner.reason ? ` — ${scanner.reason}` : ""}`);
  }
  if (report.coverage_status !== "complete") {
    lines.push("");
    lines.push("RepoRook did not complete every applicable check. Treat this as an incomplete scan, not a clean bill of health.");
  }
  if (!report.findings.length) {
    lines.push("");
    lines.push(report.coverage_status === "complete" ? "No vulnerabilities were reported by the configured scanners." : "No findings were reported within the checks that completed.");
    return lines.join("\n");
  }
  lines.push("");
  const ordered = sortBySeverity(report.findings);
  const visible = ordered.slice(0, 20);
  for (const finding of visible) {
    lines.push(`[${labels[finding.severity]}] ${compact(finding.description)}`);
    lines.push(`  Where: ${finding.file}:${finding.line}`);
    lines.push(`  Risk ID: ${finding.id} (${finding.scanner})`);
    lines.push(`  Next step: ${finding.remediation_hint}`);
    lines.push("");
  }
  if (ordered.length > visible.length) {
    lines.push(`${ordered.length - visible.length} additional findings are in .reporook/findings.json and results.sarif.`);
    lines.push("");
  }
  lines.push("Review each finding before applying a change. After fixing, run `reporook verify .`.");
  return lines.join("\n").trimEnd();
}

export function renderFinding(finding: Finding): string {
  return [
    `${labels[finding.severity]} — ${finding.description}`,
    `Location: ${finding.file}:${finding.line}`,
    `Detected by: ${finding.scanner} (${finding.rule})`,
    "",
    "What to do:",
    finding.remediation_hint,
    "",
    "Trust status: RepoRook reported this deterministically. Exploitability and any proposed patch still require review and verification.",
    ...(finding.references.length ? ["", "References:", ...finding.references.map((reference) => `- ${reference}`)] : []),
  ].join("\n");
}
