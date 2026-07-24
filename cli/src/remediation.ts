import { sha256 } from "./fingerprint.js";
import { prioritizeFindings } from "./prioritization.js";
import type { Finding, RemediationPlan, ScanReport } from "./types.js";
import { VERSION } from "./version.js";

const dependencyScanners = new Set(["npm-audit", "pip-audit", "osv-scanner"]);

function validationQuestions(finding: Finding): string[] {
  if (finding.scanner === "gitleaks") {
    return [
      "Is this a real credential or a harmless example? Do not print or copy its value while checking.",
      "Where is the credential used, and what access could it grant if it is still active?",
      "Can the code load a replacement from the project's existing secret-management mechanism?",
    ];
  }
  if (dependencyScanners.has(finding.scanner)) {
    return [
      "Is the affected package present in the resolved dependency graph and reachable in the shipped application?",
      "Is a fixed version available, and does the project's declared compatibility range permit it?",
      "Which focused and full test commands demonstrate that the upgrade preserves behavior?",
    ];
  }
  return [
    "What attacker-controlled input can reach the matched operation?",
    "Which authentication, authorization, validation, or encoding controls already constrain that path?",
    "What is the smallest change that closes the path without weakening another security control?",
  ];
}

export function createRemediationPlan(report: ScanReport, findingId: string): RemediationPlan {
  const finding = report.findings.find((candidate) => candidate.id === findingId);
  if (!finding) throw new Error(`Finding not found: ${findingId}`);
  const priority = prioritizeFindings(report).priorities.find((candidate) => candidate.finding_id === findingId);
  if (!priority) throw new Error(`Priority not found for finding: ${findingId}`);
  const identity = [
    finding.id,
    finding.fingerprint,
    report.scan_receipt.config_hash,
    report.scan_receipt.commit ?? "working-tree",
    report.scan_receipt.completed_at,
  ].join("\0");
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: VERSION },
    plan_id: `rrp-${sha256(identity).slice(0, 12)}`,
    status: "awaiting-proposal",
    generated_at: new Date().toISOString(),
    finding,
    priority,
    source_scan: report.scan_receipt,
    goal: finding.remediation_hint,
    validation_questions: validationQuestions(finding),
    scope: {
      allowed_files: [finding.file],
      related_finding_ids: priority.related_finding_ids,
      stop_if_scope_changes: true,
    },
    proposal_requirements: {
      explain_risk_in_plain_english: true,
      exact_patch_preview: true,
      behavior_impact: true,
      focused_test_plan: true,
    },
    approval: {
      required: true,
      status: "pending",
      binds_to: ["finding", "source-scan", "exact-patch", "test-plan"],
      instruction: "Show the exact diff, affected behavior, and test plan. Apply nothing until the user approves that specific proposal; ask again if any file, behavior, dependency version, or test plan changes.",
    },
    safety_rules: [
      "Keep scanner evidence separate from host-agent reasoning.",
      "If the repository changed after the source scan beyond the displayed proposal, rescan and generate a new plan before editing.",
      "Never print, copy, or place a detected secret value in a prompt, patch, test, or log.",
      "Any file beyond the starting scope must be named in the exact proposal before approval.",
      "Do not rotate credentials, create external tickets, publish advisories, or change external systems without separate authorization.",
      "Do not call the finding fixed unless the original scanner completes under the same configuration and relevant functional tests pass.",
    ],
    verification: {
      command: `reporook verify ${finding.id} . --require-scanners`,
      scanner_pass_condition: "The original scanner completes under the same configuration and reports no stable or equivalent finding.",
      functional_tests_required: true,
    },
  };
}
