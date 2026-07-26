import { mkdtemp, open, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, relative } from "node:path";
import { findingFingerprint } from "../fingerprint.js";
import { repoRelative } from "../path-utils.js";
import { runCommand } from "../process.js";
import { normalizeSeverity } from "../severity.js";
import type { Finding, ScannerAdapter, ScannerContext, ScannerResult } from "../types.js";
import { array, errored, jsonFromOutput, record, scannerParseError, scannerVersion, strings, successful, text, unavailable } from "./shared.js";

const ignoredDirectories = new Set([".git", ".reporook", ".serverless", ".terraform", "build", "dist", "node_modules", "vendor"]);
const maxFiles = 10_000;
const maxDepth = 10;

function normalized(path: string): string { return path.replaceAll("\\", "/"); }

function obviousInfrastructureFile(path: string): boolean {
  const value = normalized(path);
  const name = basename(value).toLowerCase();
  if (value.endsWith(".tf") || value.endsWith(".tf.json")) return true;
  if (name === "dockerfile" || name.startsWith("dockerfile.")) return true;
  if (/^\.github\/workflows\/[^/]+\.ya?ml$/i.test(value)) return true;
  if (["chart.yaml", "kustomization.yaml", "kustomization.yml"].includes(name)) return true;
  return /(^|\/)(?:k8s|kubernetes|manifests|charts|helm)(\/|$)/i.test(value) && /\.ya?ml$/i.test(value);
}

async function looksLikeKubernetesYaml(path: string): Promise<boolean> {
  if (!/\.ya?ml$/i.test(path)) return false;
  const handle = await open(path, "r").catch(() => null);
  if (!handle) return false;
  const buffer = Buffer.alloc(256_000);
  let bytesRead = 0;
  try { ({ bytesRead } = await handle.read(buffer, 0, buffer.length, 0)); }
  finally { await handle.close(); }
  const sample = buffer.toString("utf8", 0, bytesRead);
  return /^\s*apiVersion\s*:/m.test(sample) && /^\s*kind\s*:/m.test(sample);
}

export async function discoverCheckovFiles(target: string): Promise<string[]> {
  const matches: string[] = [];
  let visited = 0;
  const walk = async (directory: string, depth: number): Promise<void> => {
    if (depth > maxDepth || visited >= maxFiles) return;
    const entries = await readdir(directory, { withFileTypes: true }).catch(() => []);
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (visited >= maxFiles) return;
      if (entry.isSymbolicLink()) continue;
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name.toLowerCase())) await walk(absolute, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      visited += 1;
      const repositoryPath = normalized(relative(target, absolute));
      if (obviousInfrastructureFile(repositoryPath) || await looksLikeKubernetesYaml(absolute)) matches.push(repositoryPath);
    }
  };
  await walk(target, 0);
  return matches;
}

function reports(raw: unknown): Record<string, unknown>[] {
  return (Array.isArray(raw) ? raw : [raw]).map(record).filter((item) => Object.keys(item).length > 0);
}

function checkovPath(result: Record<string, unknown>, target: string): string {
  const absolute = text(result.file_abs_path);
  if (absolute) return repoRelative(target, absolute);
  return text(result.repo_file_path, text(result.file_path, "unknown")).replace(/^[/\\]+/, "").replaceAll("\\", "/");
}

export function parseCheckov(raw: unknown, target: string): Finding[] {
  const findings: Finding[] = [];
  for (const report of reports(raw)) {
    const framework = text(report.check_type, "infrastructure");
    const failed = array(record(report.results).failed_checks);
    for (const value of failed) {
      const result = record(value);
      const rule = text(result.check_id, "CKV_UNKNOWN");
      const file = checkovPath(result, target);
      const resource = text(result.resource, text(result.resource_address, "configuration"));
      const name = text(result.check_name, `Infrastructure check ${rule} failed`);
      const lineRange = array(result.file_line_range);
      const startLine = Math.max(1, Number(lineRange[0] ?? 1) || 1);
      const endLine = Math.max(startLine, Number(lineRange[1] ?? startLine) || startLine);
      const rawSeverity = text(result.severity) || text(record(result.check_result).severity) || null;
      const guideline = text(result.guideline);
      const ids = findingFingerprint(["checkov", rule, file, resource]);
      findings.push({
        ...ids,
        scanner: "checkov",
        rule,
        severity: normalizeSeverity(rawSeverity, "medium"),
        file,
        line: startLine,
        end_line: endLine,
        plain_summary: `This infrastructure configuration is missing a security safeguard: ${name.replace(/[.]+$/, "")}.`,
        description: `${name}${resource === "configuration" ? "" : ` (${resource})`}`,
        remediation_hint: `Update ${resource} so it satisfies ${rule}, then review the behavior change and rescan the infrastructure files.`,
        references: /^https?:\/\//i.test(guideline) ? [guideline] : [],
        metadata: {
          cwe: strings(result.cwe),
          cve: [],
          package: null,
          raw_severity: rawSeverity,
          tags: [`framework:${framework}`, ...(resource === "configuration" ? [] : [`resource:${resource}`])],
        },
      });
    }
  }
  return findings;
}

export class CheckovScanner implements ScannerAdapter {
  name = "checkov";

  async isApplicable(target: string) {
    return (await discoverCheckovFiles(target)).length
      ? { applicable: true }
      : { applicable: false, reason: "no Terraform, Kubernetes, Dockerfile, Helm, Kustomize, or GitHub Actions files detected" };
  }
  async version() { return scannerVersion("checkov", {}, ["--version"]); }

  async run(context: ScannerContext): Promise<ScannerResult> {
    const started = Date.now();
    const version = context.scannerVersion !== undefined ? context.scannerVersion : await scannerVersion("checkov", {}, ["--version"]);
    if (!version) return unavailable(this.name, Date.now() - started, "checkov is not installed; run `reporook setup`");
    const temporary = await mkdtemp(join(tmpdir(), "reporook-checkov-"));
    const configPath = join(temporary, "checkov.yml");
    await writeFile(configPath, "{}\n", { encoding: "utf8", mode: 0o600 });
    try {
      const args = [
        "-d", context.target,
        "--framework", "terraform", "kubernetes", "helm", "kustomize", "dockerfile", "github_actions",
        "--output", "json",
        "--compact",
        "--quiet",
        "--skip-download",
        "--config-file", configPath,
      ];
      const result = await runCommand("checkov", args, {
        cwd: temporary,
        env: {
          DOWNLOAD_EXTERNAL_MODULES: "false",
          LOG_LEVEL: "WARNING",
        },
        unsetEnv: ["BC_API_KEY", "CHECKOV_API_KEY", "CKV_API_KEY", "GITHUB_PAT", "VCS_TOKEN"],
      });
      if (result.missing) return unavailable(this.name, result.duration_ms, "checkov is not installed");
      try {
        const findings = parseCheckov(jsonFromOutput(result.stdout, result.stderr), context.target);
        if (![0, 1].includes(result.code)) {
          const failed = errored(this.name, version, result.duration_ms, result.stderr.trim() || `checkov exited ${result.code}`);
          failed.findings = findings;
          failed.status.finding_count = findings.length;
          return failed;
        }
        return successful(this.name, version, result.duration_ms, findings);
      } catch (error) {
        return errored(this.name, version, result.duration_ms, scannerParseError(error, result.stderr));
      }
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  }
}
