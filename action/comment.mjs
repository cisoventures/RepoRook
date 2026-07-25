import { readFile } from "node:fs/promises";

const marker = "<!-- reporook-security-scan -->";
const token = process.env.GITHUB_TOKEN;
const repository = process.env.GITHUB_REPOSITORY;
const issue = process.env.ISSUE_NUMBER;
const reportPath = process.env.REPORT_PATH;
const prioritiesPath = process.env.PRIORITIES_PATH;

if (!token || !repository || !issue || !reportPath) {
  process.stdout.write("RepoRook PR comment skipped because required GitHub context is unavailable.\n");
  process.exit(0);
}

let report;
try {
  report = JSON.parse(await readFile(reportPath, "utf8"));
} catch (error) {
  process.stdout.write(`RepoRook PR comment skipped: ${error.message}\n`);
  process.exit(0);
}

let priorities = null;
if (prioritiesPath) {
  try {
    priorities = JSON.parse(await readFile(prioritiesPath, "utf8"));
    if (!priorities?.summary || !Array.isArray(priorities.priorities)) priorities = null;
  }
  catch { priorities = null; }
}

const icons = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵" };
const compact = (value, limit = 240) => {
  const normalized = String(value).replace(/\s+/g, " ").trim();
  return normalized.length <= limit ? normalized : `${normalized.slice(0, limit - 1).trimEnd()}…`;
};
const markdown = (value, limit) => compact(value, limit).replaceAll("|", "\\|").replaceAll("`", "'").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
const rank = { critical: 4, high: 3, medium: 2, low: 1 };
const dependencyScanners = new Set(["npm-audit", "pip-audit", "osv-scanner"]);
const priorityByFinding = new Map((priorities?.priorities ?? []).map((item) => [item.finding_id, item.priority]));
const priorityLabel = { "fix-now": "Fix now", "fix-next": "Fix next", "review-later": "Review later" };
const policyByFinding = new Map((report.policy?.findings ?? []).map((item) => [item.finding_id, item]));
const policyLabel = { actionable: "Actionable", baseline: "Baseline", suppressed: "Suppressed", "below-threshold": "Below threshold" };
const dependencyGroups = new Map();
const items = [];
for (const finding of report.findings) {
  if (!dependencyScanners.has(finding.scanner)) {
    items.push({ severity: finding.severity, findings: [finding] });
    continue;
  }
  const key = [finding.scanner, finding.file, finding.metadata?.package ?? "unknown-package"].join("\0");
  const group = dependencyGroups.get(key) ?? [];
  group.push(finding);
  dependencyGroups.set(key, group);
}
for (const findings of dependencyGroups.values()) {
  findings.sort((a, b) => (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0));
  items.push({ severity: findings[0]?.severity ?? "low", findings });
}
items.sort((a, b) => (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0));
const visible = items.slice(0, 20);
const rows = visible.map(({ severity, findings }) => {
  const finding = findings[0];
  const dependency = dependencyScanners.has(finding.scanner);
  const location = dependency ? finding.file : `${finding.file}:${finding.line}`;
  const explanation = dependency
    ? `${finding.metadata?.package ?? "Dependency"} has ${findings.length} known advisor${findings.length === 1 ? "y" : "ies"}. ${finding.plain_summary ?? finding.description}`
    : finding.plain_summary ?? finding.description;
  const id = dependency ? `${findings.length} advisories` : finding.id;
  const policyItems = findings.map((item) => policyByFinding.get(item.id)).filter(Boolean);
  const actionable = policyItems.find((item) => item.disposition === "actionable");
  const selectedPolicy = actionable ?? policyItems[0];
  const priority = priorityByFinding.get(finding.id);
  const when = selectedPolicy ? policyLabel[selectedPolicy.disposition] : priority ? priorityLabel[priority] : "Review";
  return `| ${when} | ${icons[severity] ?? "•"} ${severity} | \`${markdown(location, 180)}\` | ${markdown(explanation, 240)} | \`${markdown(id, 80)}\` |`;
});
const shownFindings = visible.reduce((total, item) => total + item.findings.length, 0);
const omitted = Math.max(0, report.findings.length - shownFindings);
const scannerSummary = report.scanners.map((scanner) =>
  `- ${scanner.status === "ok" ? "✓" : scanner.applicable ? "⚠" : "–"} **${markdown(scanner.name, 80)}**: ${scanner.status}${scanner.reason ? ` — ${markdown(scanner.reason, 240)}` : ""}`,
).join("\n");
const body = [
  marker,
  "## RepoRook security scan",
  "",
  `**Coverage:** ${report.coverage_status} · **Critical:** ${report.summary.critical} · **High:** ${report.summary.high} · **Medium:** ${report.summary.medium} · **Low:** ${report.summary.low}`,
  ...(report.policy ? [`**Team policy:** ${report.policy.summary.actionable} actionable · ${report.policy.summary.new} new · ${report.policy.summary.existing} baseline · ${report.policy.summary.suppressed} suppressed`] : []),
  ...(priorities ? [`**Guided fix queue:** ${priorities.summary.fix_now} fix now · ${priorities.summary.fix_next} fix next · ${priorities.summary.review_later} review later`] : []),
  "",
  ...(report.coverage_status === "complete" ? [] : ["> ⚠️ This scan had incomplete coverage. No findings does not mean the repository is clean.", ""]),
  ...(report.policy?.summary?.expired_suppressions ? [`> ⚠️ ${report.policy.summary.expired_suppressions} suppression(s) expired; matching findings were evaluated normally.`, ""] : []),
  ...(rows.length ? ["| When | Severity | Location | What could be wrong | ID |", "|---|---|---|---|---|", ...rows, ""] : ["No vulnerabilities were reported by the checks that completed.", ""]),
  ...(omitted ? [`_${omitted} additional findings are available in the uploaded artifact and SARIF report._`, ""] : []),
  "<details><summary>Scanner coverage</summary>", "", scannerSummary, "", "</details>", "",
  ...(report.policy && report.policy.summary.actionable === 0
    ? ["No policy-actionable findings are queued. Baseline and active suppressed findings remain visible for audit; do not modify them without explicit direction."]
    : ["Ask your coding agent: **“Read the RepoRook priorities, prepare a guided plan for the first fix-now finding, and show me the exact patch and test plan. Wait for my approval, record the approval receipt, then run tests and RepoRook verification.”**"]),
].join("\n");

const headers = {
  authorization: `Bearer ${token}`,
  accept: "application/vnd.github+json",
  "x-github-api-version": "2022-11-28",
  "content-type": "application/json",
};
const baseUrl = `https://api.github.com/repos/${repository}/issues/${issue}/comments`;
const listResponse = await fetch(`${baseUrl}?per_page=100`, { headers });
if (!listResponse.ok) throw new Error(`Could not list PR comments: ${listResponse.status}`);
const comments = await listResponse.json();
const existing = comments.find((comment) => typeof comment.body === "string" && comment.body.includes(marker));
const url = existing ? `https://api.github.com/repos/${repository}/issues/comments/${existing.id}` : baseUrl;
const response = await fetch(url, { method: existing ? "PATCH" : "POST", headers, body: JSON.stringify({ body }) });
if (!response.ok) throw new Error(`Could not ${existing ? "update" : "create"} PR comment: ${response.status}`);
process.stdout.write(`RepoRook PR comment ${existing ? "updated" : "created"}.\n`);
