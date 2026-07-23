import { access, readdir } from "node:fs/promises";
import { basename, join } from "node:path";
import { findingFingerprint } from "../fingerprint.js";
import { plainSummary } from "../knowledge.js";
import { runCommand } from "../process.js";
import type { Finding, ScannerAdapter, ScannerContext, ScannerResult } from "../types.js";
import { array, errored, jsonFromOutput, record, scannerParseError, scannerVersion, successful, text, unavailable } from "./shared.js";

async function requirementFiles(target: string): Promise<string[]> {
  let names: string[] = [];
  try { names = await readdir(target); } catch { return []; }
  return names.filter((name) => /^requirements.*\.txt$/i.test(name)).map((name) => join(target, name));
}

async function exists(path: string): Promise<boolean> { try { await access(path); return true; } catch { return false; } }

export function parsePipAudit(raw: unknown, sourceFile: string): Finding[] {
  const root = record(raw);
  return array(root.dependencies).flatMap((dependencyValue) => {
    const dependency = record(dependencyValue);
    const packageName = text(dependency.name, "unknown-package");
    const installed_version = text(dependency.version) || null;
    return array(dependency.vulns).map((vulnerabilityValue) => {
      const vulnerability = record(vulnerabilityValue);
      const advisoryId = text(vulnerability.id, "unknown-advisory");
      const aliases = array(vulnerability.aliases).map(String);
      const fixed_versions = array(vulnerability.fix_versions).map(String);
      const ids = findingFingerprint(["pip-audit", packageName, advisoryId]);
      return {
        ...ids,
        scanner: "pip-audit",
        rule: `pip-audit:${advisoryId}`,
        severity: "high",
        file: sourceFile,
        line: 1,
        plain_summary: plainSummary({ scanner: "pip-audit", rule: `pip-audit:${advisoryId}`, packageName }),
        description: text(vulnerability.description, `${packageName} ${installed_version ?? ""} is affected by ${advisoryId}.`).trim(),
        remediation_hint: fixed_versions.length
          ? `Upgrade ${packageName} to ${fixed_versions.join(" or ")} and run the repository test suite.`
          : `Review ${advisoryId} and replace or constrain ${packageName}; no fixed version was reported.`,
        references: [`https://osv.dev/vulnerability/${encodeURIComponent(advisoryId)}`],
        metadata: {
          cwe: [],
          cve: [advisoryId, ...aliases].filter((value) => value.startsWith("CVE-")),
          package: packageName,
          installed_version,
          fixed_versions,
          raw_severity: null,
        },
      } satisfies Finding;
    });
  });
}

export class PipAuditScanner implements ScannerAdapter {
  name = "pip-audit";
  async isApplicable(target: string) {
    const requirements = await requirementFiles(target);
    const locked = await exists(join(target, "poetry.lock")) || await exists(join(target, "uv.lock"));
    return requirements.length || locked ? { applicable: true } : { applicable: false, reason: "no supported Python dependency file detected" };
  }

  async run(context: ScannerContext): Promise<ScannerResult> {
    const version = await scannerVersion("pip-audit");
    if (!version) return unavailable(this.name, 0, "pip-audit is not installed; run `reporook setup`");
    const requirements = await requirementFiles(context.target);
    const invocations: Array<{ args: string[]; source: string }> = requirements.map((file) => ({ args: ["-r", file, "-f", "json"], source: basename(file) }));
    if (!invocations.length) invocations.push({ args: ["--locked", context.target, "-f", "json"], source: await exists(join(context.target, "uv.lock")) ? "uv.lock" : "poetry.lock" });
    const findings: Finding[] = [];
    let duration_ms = 0;
    for (const invocation of invocations) {
      const result = await runCommand("pip-audit", invocation.args, { cwd: context.target });
      duration_ms += result.duration_ms;
      if (result.missing) return unavailable(this.name, duration_ms, "pip-audit is not installed");
      try {
        findings.push(...parsePipAudit(jsonFromOutput(result.stdout, result.stderr), invocation.source));
      } catch (error) {
        return errored(this.name, version, duration_ms, scannerParseError(error, result.stderr));
      }
      if (![0, 1].includes(result.code)) return errored(this.name, version, duration_ms, result.stderr.trim() || `pip-audit exited ${result.code}`);
    }
    return successful(this.name, version, duration_ms, findings);
  }
}
