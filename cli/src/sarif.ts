import type { Finding, ScanReport } from "./types.js";

function level(finding: Finding): "error" | "warning" | "note" {
  if (["critical", "high"].includes(finding.severity)) return "error";
  return finding.severity === "medium" ? "warning" : "note";
}

export function toSarif(report: ScanReport): Record<string, unknown> {
  const rules = new Map<string, Finding>();
  for (const finding of report.findings) if (!rules.has(finding.rule)) rules.set(finding.rule, finding);
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "RepoRook",
          version: report.tool.version,
          informationUri: "https://github.com/cisoventures/RepoRook",
          rules: [...rules.values()].map((finding) => ({
            id: finding.rule,
            name: finding.rule.replace(/[^a-zA-Z0-9]+/g, "_").slice(0, 120),
            shortDescription: { text: finding.description },
            help: { text: `${finding.description}\n\nRemediation: ${finding.remediation_hint}` },
            properties: { tags: [finding.scanner, ...finding.metadata.cwe, ...finding.metadata.cve] },
          })),
        },
      },
      automationDetails: { id: `reporook/${report.target.commit ?? "working-tree"}` },
      properties: { coverage_status: report.coverage_status, scan_receipt: report.scan_receipt },
      results: report.findings.map((finding) => ({
        ruleId: finding.rule,
        level: level(finding),
        message: { text: `${finding.description} ${finding.remediation_hint}` },
        locations: [{ physicalLocation: {
          artifactLocation: { uri: finding.file, uriBaseId: "%SRCROOT%" },
          region: { startLine: Math.max(1, finding.line), ...(finding.end_line ? { endLine: finding.end_line } : {}), ...(finding.column ? { startColumn: finding.column } : {}) },
        } }],
        partialFingerprints: { primaryLocationLineHash: finding.fingerprint },
        fingerprints: { reporookFingerprint: finding.fingerprint },
        properties: { id: finding.id, scanner: finding.scanner, severity: finding.severity, references: finding.references },
      })),
    }],
  };
}
