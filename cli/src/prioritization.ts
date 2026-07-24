import type { Finding, PrioritizationReport, PrioritizedFinding, PriorityBand, ScanReport, Severity } from "./types.js";
import { VERSION } from "./version.js";

const severityScore: Record<Severity, number> = { critical: 400, high: 300, medium: 200, low: 100 };
const dependencyScanners = new Set(["npm-audit", "pip-audit", "osv-scanner"]);

function exposesCredential(finding: Finding): boolean {
  return finding.scanner === "gitleaks"
    || finding.metadata.cwe.some((value) => /CWE-(?:259|798)\b/i.test(value));
}

function band(finding: Finding): PriorityBand {
  if (exposesCredential(finding) || finding.severity === "critical" || finding.severity === "high") return "fix-now";
  if (finding.severity === "medium") return "fix-next";
  return "review-later";
}

function score(finding: Finding): number {
  return severityScore[finding.severity]
    + (exposesCredential(finding) ? 40 : 0)
    + (finding.metadata.fixed_versions?.length ? 10 : 0)
    + (finding.metadata.tags?.includes("direct-dependency") ? 5 : 0);
}

function reason(finding: Finding, priority: PriorityBand): string {
  if (exposesCredential(finding)) {
    return "A credential may be exposed. Treat it as usable until its provider confirms otherwise; remove it from code without printing its value, then revoke and replace it outside the repository.";
  }
  if (finding.metadata.package && finding.metadata.fixed_versions?.length) {
    return `${finding.severity[0]?.toUpperCase()}${finding.severity.slice(1)}-severity dependency risk with a known fixed version (${finding.metadata.fixed_versions.join(" or ")}). Confirm compatibility and test the upgrade before release.`;
  }
  if (finding.metadata.package) {
    return `${finding.severity[0]?.toUpperCase()}${finding.severity.slice(1)}-severity dependency risk. Confirm that the package is present in the shipped dependency graph, identify a compatible remediation, and test the resulting upgrade or replacement.`;
  }
  if (priority === "fix-now") {
    return `${finding.severity[0]?.toUpperCase()}${finding.severity.slice(1)}-severity scanner evidence can represent material impact. Validate whether untrusted input can reach it and resolve it before release if applicable.`;
  }
  if (priority === "fix-next") {
    return "This medium-severity finding deserves focused review after release-blocking items. Validate reachability and schedule a bounded fix with a regression test.";
  }
  return "This lower-severity finding is not the first release blocker, but it should be reviewed, documented, and fixed when the surrounding code is next changed.";
}

function relatedFindings(report: ScanReport, finding: Finding): string[] {
  if (!dependencyScanners.has(finding.scanner) || !finding.metadata.package) return [];
  return report.findings
    .filter((candidate) => candidate.id !== finding.id
      && candidate.scanner === finding.scanner
      && candidate.file === finding.file
      && candidate.metadata.package === finding.metadata.package)
    .map((candidate) => candidate.id)
    .sort();
}

export function prioritizeFindings(report: ScanReport): PrioritizationReport {
  const ordered = [...report.findings].sort((left, right) =>
    score(right) - score(left)
    || left.file.localeCompare(right.file)
    || left.line - right.line
    || left.id.localeCompare(right.id));
  const priorities: PrioritizedFinding[] = ordered.map((finding, index) => {
    const priority = band(finding);
    return {
      rank: index + 1,
      priority,
      finding_id: finding.id,
      severity: finding.severity,
      scanner: finding.scanner,
      package: finding.metadata.package,
      file: finding.file,
      line: finding.line,
      title: finding.plain_summary,
      reason: reason(finding, priority),
      next_step: finding.remediation_hint,
      related_finding_ids: relatedFindings(report, finding),
    };
  });
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: VERSION },
    generated_at: report.generated_at,
    coverage_status: report.coverage_status,
    source_scan: report.scan_receipt,
    summary: {
      fix_now: priorities.filter((item) => item.priority === "fix-now").length,
      fix_next: priorities.filter((item) => item.priority === "fix-next").length,
      review_later: priorities.filter((item) => item.priority === "review-later").length,
      total: priorities.length,
    },
    priorities,
  };
}
