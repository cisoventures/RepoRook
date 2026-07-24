import { sortBySeverity } from "./severity.js";
import { prioritizeFindings } from "./prioritization.js";
import type { Finding, PrioritizationReport, RemediationPlan, ScanReport, Severity, VerificationReport } from "./types.js";

const labels: Record<Severity, string> = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" };
const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const dependencyScanners = new Set(["npm-audit", "pip-audit", "osv-scanner"]);

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
  const codeFindings = ordered.filter((finding) => !dependencyScanners.has(finding.scanner));
  const dependencyGroups = new Map<string, Finding[]>();
  for (const finding of ordered.filter((candidate) => dependencyScanners.has(candidate.scanner))) {
    const key = [finding.scanner, finding.file, finding.metadata.package ?? "unknown-package"].join("\0");
    const group = dependencyGroups.get(key) ?? [];
    group.push(finding);
    dependencyGroups.set(key, group);
  }
  const items: Array<{ severity: Severity; findings: Finding[] }> = [
    ...codeFindings.map((finding) => ({ severity: finding.severity, findings: [finding] })),
    ...[...dependencyGroups.values()].map((findings) => ({ severity: findings[0]?.severity ?? "low", findings })),
  ].sort((a, b) => rank[b.severity] - rank[a.severity]);
  const visible = items.slice(0, 20);
  for (const item of visible) {
    const finding = item.findings[0];
    if (!finding) continue;
    if (item.findings.length > 1 || dependencyScanners.has(finding.scanner)) {
      const packageName = finding.metadata.package ?? "unknown package";
      const rules = item.findings.slice(0, 4).map((candidate) => candidate.rule.replace(/^(?:(?:npm|pip)-audit|osv-scanner):/, "")).join(", ");
      lines.push(`[${labels[item.severity]}] ${packageName} — ${item.findings.length} known advisor${item.findings.length === 1 ? "y" : "ies"}`);
      lines.push(`  What this means: ${compact(finding.plain_summary)}`);
      lines.push(`  Where: ${finding.file}`);
      lines.push(`  Advisories: ${rules}${item.findings.length > 4 ? ` (+${item.findings.length - 4} more)` : ""}`);
      lines.push(`  Next step: ${finding.remediation_hint}`);
      lines.push("");
      continue;
    }
    lines.push(`[${labels[finding.severity]}] ${compact(finding.plain_summary)}`);
    lines.push(`  Where: ${finding.file}:${finding.line}`);
    lines.push(`  Risk ID: ${finding.id} (${finding.scanner})`);
    lines.push(`  Scanner detail: ${compact(finding.description)}`);
    lines.push(`  Next step: ${finding.remediation_hint}`);
    lines.push("");
  }
  if (items.length > visible.length) {
    lines.push(`Additional findings are in .reporook/findings.json and results.sarif.`);
    lines.push("");
  }
  lines.push("Review each finding before applying a change. After fixing one, run `reporook verify FINDING_ID .`.");
  lines.push("Want agent help? Use the generated `agent-prompt.txt`; it requires approval before edits and verification afterward.");
  return lines.join("\n").trimEnd();
}

export function renderAgentPrompt(report: ScanReport, findingsPath = ".reporook/findings.json"): string {
  const priorities = prioritizeFindings(report);
  const first = priorities.priorities[0];
  const highest = first ? report.findings.find((finding) => finding.id === first.finding_id) : undefined;
  const priority = highest ? `${highest.severity} finding ${highest.id}` : "scanner coverage and the absence of findings";
  return [
    "Help me review and safely resolve this RepoRook security scan.",
    "",
    `Read the deterministic evidence in ${findingsPath}.`,
    `The scan reported ${report.summary.total} finding(s) with ${report.coverage_status} coverage. Start with the ${priority}.`,
    "",
    "Work one finding at a time:",
    "1. Explain the risk and likely real-world impact in plain English.",
    "2. Inspect the nearby code and say whether the finding appears applicable. Keep your reasoning separate from RepoRook's evidence.",
    `3. Run \`reporook plan ${highest?.id ?? "FINDING_ID"} .\` and use its finding-bound plan to prepare the smallest safe change and a focused regression test.`,
    "4. Show me the exact diff, behavior impact, and test plan. Do not edit files until I approve that exact change and test plan.",
    `5. After approval, apply only the approved change, run the focused test and relevant project tests, then run \`reporook verify ${highest?.id ?? "FINDING_ID"} . --require-scanners\`.`,
    "6. Call the finding fixed only if verification passes with the original scanner and configuration and the relevant tests pass. Treat incomplete coverage as inconclusive.",
    "",
    "Never print or repeat detected secret values. If a real credential is exposed, tell me it must be revoked and replaced outside the repository.",
  ].join("\n");
}

export function renderPrioritization(report: PrioritizationReport): string {
  const lines = [
    "RepoRook fix priorities",
    `Finding counts: ${report.summary.fix_now} fix now | ${report.summary.fix_next} fix next | ${report.summary.review_later} review later`,
    "Related package advisories are grouped into one human action below while remaining separate in JSON.",
  ];
  if (report.coverage_status !== "complete") {
    lines.push("", "Coverage is incomplete. These priorities cover reported findings only; missing scanner evidence may change the order.");
  }
  if (!report.priorities.length) {
    lines.push("", report.coverage_status === "complete" ? "No reported findings need prioritization." : "No findings were reported by the checks that completed.");
    return lines.join("\n");
  }
  const byId = new Map(report.priorities.map((item) => [item.finding_id, item]));
  const seen = new Set<string>();
  const groups: Array<{ primary: PrioritizationReport["priorities"][number]; members: PrioritizationReport["priorities"] }> = [];
  for (const item of report.priorities) {
    if (seen.has(item.finding_id)) continue;
    const memberIds = item.package ? [item.finding_id, ...item.related_finding_ids] : [item.finding_id];
    const members = memberIds.map((id) => byId.get(id)).filter((value): value is PrioritizationReport["priorities"][number] => value !== undefined).sort((left, right) => left.rank - right.rank);
    for (const member of members) seen.add(member.finding_id);
    groups.push({ primary: members[0] ?? item, members });
  }
  for (const [index, group] of groups.slice(0, 20).entries()) {
    const item = group.primary;
    const dependency = item.package !== null;
    lines.push(
      "",
      `${index + 1}. ${item.priority.toUpperCase()} — ${item.severity.toUpperCase()} ${dependency ? `${item.package} (${group.members.length} advisor${group.members.length === 1 ? "y" : "ies"})` : item.finding_id}`,
      `   ${compact(item.title)}`,
      `   Where: ${item.file}:${item.line}`,
      `   Why: ${compact(item.reason, 360)}`,
      `   Next: ${compact(item.next_step, 360)}`,
      ...(dependency ? [`   Finding IDs: ${group.members.map((member) => member.finding_id).join(", ")}`] : []),
    );
  }
  if (groups.length > 20) lines.push("", `${groups.length - 20} additional fix groups are in priorities.json.`);
  lines.push("", `Start one guided fix with \`reporook plan ${report.priorities[0]?.finding_id ?? "FINDING_ID"} .\`.`);
  return lines.join("\n");
}

export function renderRemediationPlan(plan: RemediationPlan): string {
  return [
    "RepoRook guided fix plan",
    `Plan: ${plan.plan_id}`,
    `Priority: ${plan.priority.priority.toUpperCase()} | Finding: ${plan.finding.id} | Severity: ${plan.finding.severity.toUpperCase()}`,
    `What could happen: ${plan.finding.plain_summary}`,
    `Where: ${plan.finding.file}:${plan.finding.line}`,
    `Goal: ${plan.goal}`,
    "",
    "Before editing:",
    ...plan.validation_questions.map((question, index) => `${index + 1}. ${question}`),
    "",
    "Approval required: show the exact diff, behavior impact, and test plan. Apply nothing until that specific proposal is approved.",
    `After tests, verify with: ${plan.verification.command}`,
  ].join("\n");
}

export function renderRemediationPrompt(plan: RemediationPlan, planPath: string, findingsPath: string): string {
  return [
    `Help me safely resolve RepoRook finding ${plan.finding.id}.`,
    "",
    `Read the deterministic finding in ${findingsPath} and the bound remediation plan in ${planPath}.`,
    `Plan ID: ${plan.plan_id}. Source commit: ${plan.source_scan.commit ?? "working tree"}.`,
    "",
    "Before editing any application file:",
    "1. Answer the plan's validation questions using repository evidence. Label unsupported conclusions as agent hypotheses.",
    "2. Explain the likely impact in plain English.",
    "3. Show the smallest exact diff, every file it changes, the behavior impact, and the focused plus relevant test commands.",
    "4. Ask me to approve that exact proposal. Do not treat approval of a different plan, file list, dependency version, or diff as permission.",
    "5. If the repository changed after the source scan beyond this proposal, rescan and prepare a new plan.",
    "",
    "After approval, apply only the approved patch. Stop and ask again if scope changes. Run the approved tests, then run:",
    `  ${plan.verification.command}`,
    "",
    "Report scanner resolution, functional tests, and remaining proof gaps separately. Never print a detected secret value or call an inconclusive result fixed.",
  ].join("\n");
}

export function renderVerification(report: VerificationReport): string {
  const heading = report.scanner_resolution === "passed"
    ? "PASSED — the scanner no longer reports this finding"
    : report.scanner_resolution === "failed"
      ? "FAILED — the finding is still present"
      : "INCONCLUSIVE — scanner evidence is incomplete";
  return [
    `RepoRook verification: ${heading}`,
    `Finding: ${report.finding_id}`,
    `Reason: ${report.reason}`,
    "Functional tests: not recorded by RepoRook. Run and report the focused and relevant project tests separately.",
    report.scanner_resolution === "passed"
      ? "Scanner resolution passed, but call the fix verified only after the relevant tests also pass."
      : "Do not call this finding fixed.",
  ].join("\n");
}

export function renderFinding(finding: Finding): string {
  return [
    `${labels[finding.severity]} — ${finding.plain_summary}`,
    `Location: ${finding.file}:${finding.line}`,
    `Detected by: ${finding.scanner} (${finding.rule})`,
    `Scanner detail: ${finding.description}`,
    "",
    "What to do:",
    finding.remediation_hint,
    "",
    "Trust status: RepoRook reported this deterministically. Exploitability and any proposed patch still require review and verification.",
    ...(finding.references.length ? ["", "References:", ...finding.references.map((reference) => `- ${reference}`)] : []),
  ].join("\n");
}
