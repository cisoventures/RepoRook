import { readFile } from "node:fs/promises";

const marker = "<!-- reporook-security-scan -->";
const token = process.env.GITHUB_TOKEN;
const repository = process.env.GITHUB_REPOSITORY;
const issue = process.env.ISSUE_NUMBER;
const reportPath = process.env.REPORT_PATH;

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

const icons = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵" };
const compact = (value, limit = 240) => {
  const normalized = String(value).replace(/\s+/g, " ").trim();
  return normalized.length <= limit ? normalized : `${normalized.slice(0, limit - 1).trimEnd()}…`;
};
const markdown = (value, limit) => compact(value, limit).replaceAll("|", "\\|").replaceAll("`", "'").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
const rows = report.findings.slice(0, 20).map((finding) =>
  `| ${icons[finding.severity] ?? "•"} ${finding.severity} | \`${markdown(`${finding.file}:${finding.line}`, 180)}\` | ${markdown(finding.description, 240)} | \`${finding.id}\` |`,
);
const omitted = Math.max(0, report.findings.length - rows.length);
const scannerSummary = report.scanners.map((scanner) =>
  `- ${scanner.status === "ok" ? "✓" : scanner.applicable ? "⚠" : "–"} **${markdown(scanner.name, 80)}**: ${scanner.status}${scanner.reason ? ` — ${markdown(scanner.reason, 240)}` : ""}`,
).join("\n");
const body = [
  marker,
  "## RepoRook security scan",
  "",
  `**Coverage:** ${report.coverage_status} · **Critical:** ${report.summary.critical} · **High:** ${report.summary.high} · **Medium:** ${report.summary.medium} · **Low:** ${report.summary.low}`,
  "",
  ...(report.coverage_status === "complete" ? [] : ["> ⚠️ This scan had incomplete coverage. No findings does not mean the repository is clean.", ""]),
  ...(rows.length ? ["| Severity | Location | What could be wrong | ID |", "|---|---|---|---|", ...rows, ""] : ["No vulnerabilities were reported by the checks that completed.", ""]),
  ...(omitted ? [`_${omitted} additional findings are available in the uploaded artifact and SARIF report._`, ""] : []),
  "<details><summary>Scanner coverage</summary>", "", scannerSummary, "", "</details>", "",
  "Ask your coding agent: **“Explain the RepoRook findings and help me fix them one at a time.”**",
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
