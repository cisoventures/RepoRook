import { access } from "node:fs/promises";
import { join } from "node:path";
import { findingFingerprint } from "../fingerprint.js";
import { runCommand } from "../process.js";
import { normalizeSeverity } from "../severity.js";
import type { Finding, ScannerAdapter, ScannerContext, ScannerResult } from "../types.js";
import { array, errored, jsonFromOutput, record, scannerVersion, successful, text, unavailable } from "./shared.js";

async function exists(path: string): Promise<boolean> { try { await access(path); return true; } catch { return false; } }

export function parseNpmAudit(raw: unknown): Finding[] {
  const root = record(raw);
  const vulnerabilities = record(root.vulnerabilities);
  const findings: Finding[] = [];
  for (const [packageName, value] of Object.entries(vulnerabilities)) {
    const vulnerability = record(value);
    const advisories = array(vulnerability.via).filter((via) => typeof via === "object");
    const effective = advisories.length ? advisories : [vulnerability];
    for (const item of effective) {
      const advisory = record(item);
      const source = text(advisory.source, text(advisory.url, packageName));
      const ids = findingFingerprint(["npm-audit", packageName, source]);
      const severityRaw = text(advisory.severity, text(vulnerability.severity, "unknown"));
      findings.push({
        ...ids,
        scanner: "npm-audit",
        rule: `npm-audit:${source}`,
        severity: normalizeSeverity(severityRaw, "high"),
        file: "package-lock.json",
        line: 1,
        description: text(advisory.title, `${packageName} has a known security advisory.`),
        remediation_hint: typeof vulnerability.fixAvailable === "object"
          ? `Upgrade ${packageName} to a non-vulnerable version and run the repository test suite.`
          : `Review available upgrades for ${packageName}; confirm compatibility and run tests after updating.`,
        references: text(advisory.url) ? [text(advisory.url)] : [],
        metadata: {
          cwe: array(advisory.cwe).map(String),
          cve: [],
          package: packageName,
          raw_severity: severityRaw,
          tags: vulnerability.isDirect ? ["direct-dependency"] : ["transitive-dependency"],
        },
      });
    }
  }
  const legacy = record(root.advisories);
  for (const [source, value] of Object.entries(legacy)) {
    const advisory = record(value);
    const packageName = text(advisory.module_name, "unknown-package");
    const ids = findingFingerprint(["npm-audit", packageName, source]);
    findings.push({
      ...ids,
      scanner: "npm-audit",
      rule: `npm-audit:${source}`,
      severity: normalizeSeverity(advisory.severity, "high"),
      file: "package-lock.json",
      line: 1,
      description: text(advisory.title, `${packageName} has a known security advisory.`),
      remediation_hint: `Upgrade ${packageName} outside the vulnerable range ${text(advisory.vulnerable_versions)} and run tests.`,
      references: text(advisory.url) ? [text(advisory.url)] : [],
      metadata: { cwe: array(advisory.cwe).map(String), cve: array(advisory.cves).map(String), package: packageName, raw_severity: text(advisory.severity) || null },
    });
  }
  return findings;
}

export class NpmAuditScanner implements ScannerAdapter {
  name = "npm-audit";
  async isApplicable(target: string) {
    return await exists(join(target, "package-lock.json"))
      ? { applicable: true }
      : { applicable: false, reason: "no package-lock.json detected" };
  }

  async run(context: ScannerContext): Promise<ScannerResult> {
    const version = await scannerVersion("npm");
    if (!version) return unavailable(this.name, 0, "npm is not installed");
    const result = await runCommand("npm", ["audit", "--json"], { cwd: context.target });
    if (result.missing) return unavailable(this.name, result.duration_ms, "npm is not installed");
    try {
      const findings = parseNpmAudit(jsonFromOutput(result.stdout, result.stderr));
      if (![0, 1].includes(result.code)) return errored(this.name, version, result.duration_ms, result.stderr.trim() || `npm audit exited ${result.code}`);
      return successful(this.name, version, result.duration_ms, findings);
    } catch (error) {
      return errored(this.name, version, result.duration_ms, (error as Error).message);
    }
  }
}
