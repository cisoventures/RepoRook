import { readdir } from "node:fs/promises";
import { basename, join, relative } from "node:path";
import { findingFingerprint } from "../fingerprint.js";
import { plainSummary } from "../knowledge.js";
import { repoRelative } from "../path-utils.js";
import { runCommand } from "../process.js";
import { normalizeSeverity } from "../severity.js";
import type { Finding, ScannerAdapter, ScannerContext, ScannerResult, Severity } from "../types.js";
import { array, errored, jsonFromOutput, record, scannerParseError, scannerVersion, strings, successful, text, unavailable } from "./shared.js";

const supportedNames = new Set([
  "bun.lock",
  "bun.lockb",
  "buildscript-gradle.lockfile",
  "cabal.project.freeze",
  "Cargo.lock",
  "composer.lock",
  "conan.lock",
  "deps.json",
  "Gemfile.lock",
  "gems.locked",
  "go.mod",
  "gradle.lockfile",
  "mix.lock",
  "osv-scanner-custom.json",
  "package-lock.json",
  "packages.config",
  "packages.lock.json",
  "pdm.lock",
  "Pipfile.lock",
  "pnpm-lock.yaml",
  "poetry.lock",
  "pom.xml",
  "pubspec.lock",
  "pylock.toml",
  "renv.lock",
  "stack.yaml.lock",
  "uv.lock",
  "yarn.lock",
]);

const skippedDirectories = new Set([
  ".git",
  ".gradle",
  ".reporook",
  ".venv",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "target",
  "vendor",
  "venv",
]);

function isRequirementsFile(name: string): boolean {
  return /^requirements.*\.txt$/i.test(name);
}

function isSupportedLockfile(relativePath: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/");
  const name = basename(normalized);
  return supportedNames.has(name)
    || isRequirementsFile(name)
    || normalized.toLowerCase().endsWith("gradle/verification-metadata.xml");
}

function handledByNativeRootScanner(relativePath: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/");
  if (normalized.includes("/")) return false;
  const name = normalized.toLowerCase();
  return name === "package-lock.json"
    || name === "poetry.lock"
    || name === "uv.lock"
    || isRequirementsFile(name);
}

export async function discoverOsvLockfiles(target: string): Promise<string[]> {
  const found: string[] = [];
  const walk = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const absolute = join(directory, entry.name);
      const relativePath = relative(target, absolute).replaceAll("\\", "/");
      if (entry.isDirectory()) {
        if (!skippedDirectories.has(entry.name.toLowerCase())) await walk(absolute);
        continue;
      }
      if (!entry.isFile() || handledByNativeRootScanner(relativePath) || !isSupportedLockfile(relativePath)) continue;
      found.push(absolute);
    }
  };
  await walk(target);
  return found.sort((left, right) => left.localeCompare(right));
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function osvSeverity(value: unknown, fallback: unknown): Severity {
  const score = Number.parseFloat(String(value ?? ""));
  if (Number.isFinite(score)) {
    if (score >= 9) return "critical";
    if (score >= 7) return "high";
    if (score >= 4) return "medium";
    return "low";
  }
  return normalizeSeverity(fallback, "high");
}

function fixedVersions(vulnerabilities: Record<string, unknown>[], packageName: string): string[] {
  const fixed: string[] = [];
  for (const vulnerability of vulnerabilities) {
    for (const affectedValue of array(vulnerability.affected)) {
      const affected = record(affectedValue);
      const affectedPackage = record(affected.package);
      if (text(affectedPackage.name) && text(affectedPackage.name) !== packageName) continue;
      for (const rangeValue of array(affected.ranges)) {
        const range = record(rangeValue);
        for (const eventValue of array(range.events)) {
          const version = text(record(eventValue).fixed);
          if (version) fixed.push(version);
        }
      }
    }
  }
  return unique(fixed);
}

function relatedVulnerabilities(vulnerabilities: Record<string, unknown>[], ids: string[]): Record<string, unknown>[] {
  const group = new Set(ids);
  const related = vulnerabilities.filter((vulnerability) => {
    if (group.has(text(vulnerability.id))) return true;
    return strings(vulnerability.aliases).some((alias) => group.has(alias));
  });
  return related.length ? related : vulnerabilities.slice(0, 1);
}

function conciseDescription(value: string, fallback: string): string {
  const normalized = value.replace(/\s+/g, " ").trim();
  if (!normalized) return fallback;
  return normalized.length <= 1_000 ? normalized : `${normalized.slice(0, 999).trimEnd()}…`;
}

export function parseOsvScanner(raw: unknown, target: string): Finding[] {
  const root = record(raw);
  const findings: Finding[] = [];
  for (const resultValue of array(root.results)) {
    const result = record(resultValue);
    const source = record(result.source);
    const file = repoRelative(target, text(source.path), "dependency manifest");
    for (const packageValue of array(result.packages)) {
      const packageResult = record(packageValue);
      const packageInfo = record(packageResult.package);
      const packageName = text(packageInfo.name, "unknown-package");
      const installedVersion = text(packageInfo.version) || null;
      const ecosystem = text(packageInfo.ecosystem, "unknown");
      const vulnerabilities = array(packageResult.vulnerabilities).map(record);
      const groups = array(packageResult.groups).map(record);
      const effectiveGroups: Record<string, unknown>[] = groups.length
        ? groups
        : vulnerabilities.map((vulnerability) => record({ ids: [text(vulnerability.id, "unknown-advisory")], aliases: strings(vulnerability.aliases) }));

      for (const group of effectiveGroups) {
        const ids = unique(strings(group.ids));
        const aliases = unique([...strings(group.aliases), ...ids]);
        const advisoryId = ids[0] ?? aliases[0] ?? "unknown-advisory";
        const related = relatedVulnerabilities(vulnerabilities, ids.length ? ids : [advisoryId]);
        const primary = related[0] ?? {};
        const databaseSpecific = record(primary.database_specific);
        const rawSeverity = text(group.max_severity) || text(databaseSpecific.severity) || null;
        const fixed_versions = fixedVersions(related, packageName);
        const cwe = unique(related.flatMap((vulnerability) => strings(record(vulnerability.database_specific).cwe_ids)));
        const cve = unique([
          ...aliases,
          ...related.flatMap((vulnerability) => strings(vulnerability.aliases)),
          ...related.map((vulnerability) => text(vulnerability.id)),
        ].filter((value) => /^CVE-/i.test(value)).map((value) => value.toUpperCase()));
        const references = unique([
          `https://osv.dev/vulnerability/${encodeURIComponent(advisoryId)}`,
          ...related.flatMap((vulnerability) => array(vulnerability.references).map((referenceValue) => text(record(referenceValue).url))),
        ]).slice(0, 10);
        const description = conciseDescription(
          text(primary.summary, text(primary.details)),
          `${packageName} ${installedVersion ?? ""} is affected by ${advisoryId}.`.trim(),
        );
        const fingerprint = findingFingerprint(["osv-scanner", ecosystem, packageName, advisoryId]);
        findings.push({
          ...fingerprint,
          scanner: "osv-scanner",
          rule: `osv-scanner:${advisoryId}`,
          severity: osvSeverity(group.max_severity, databaseSpecific.severity),
          file,
          line: 1,
          plain_summary: plainSummary({ scanner: "osv-scanner", rule: `osv-scanner:${advisoryId}`, packageName }),
          description,
          remediation_hint: fixed_versions.length
            ? `Upgrade ${packageName} to ${fixed_versions.join(" or ")} and run the repository test suite.`
            : `Review ${advisoryId} and replace or constrain ${packageName}; OSV did not report a fixed version.`,
          references,
          metadata: {
            cwe,
            cve,
            package: packageName,
            installed_version: installedVersion,
            fixed_versions,
            raw_severity: rawSeverity,
            tags: [`ecosystem:${ecosystem}`],
          },
        });
      }
    }
  }
  return findings;
}

export class OsvScanner implements ScannerAdapter {
  name = "osv-scanner";

  async isApplicable(target: string) {
    return (await discoverOsvLockfiles(target)).length
      ? { applicable: true }
      : { applicable: false, reason: "no complementary OSV-supported dependency files detected" };
  }

  async run(context: ScannerContext): Promise<ScannerResult> {
    const started = Date.now();
    const version = await scannerVersion("osv-scanner");
    if (!version) return unavailable(this.name, Date.now() - started, "osv-scanner is not installed; run `reporook setup`");
    const lockfiles = await discoverOsvLockfiles(context.target);
    if (!lockfiles.length) return errored(this.name, version, Date.now() - started, "OSV-supported dependency files disappeared before the scan started");
    const args = ["scan", "source", "--format=json", "--verbosity=error"];
    for (const lockfile of lockfiles) args.push("--lockfile", lockfile);
    const result = await runCommand("osv-scanner", args, { cwd: context.target });
    if (result.missing) return unavailable(this.name, result.duration_ms, "osv-scanner is not installed");
    try {
      const findings = parseOsvScanner(jsonFromOutput(result.stdout, result.stderr), context.target);
      if (![0, 1].includes(result.code)) {
        const failed = errored(this.name, version, result.duration_ms, result.stderr.trim() || `osv-scanner exited ${result.code}`);
        failed.findings = findings;
        failed.status.finding_count = findings.length;
        return failed;
      }
      return successful(this.name, version, result.duration_ms, findings);
    } catch (error) {
      return errored(this.name, version, result.duration_ms, scannerParseError(error, result.stderr));
    }
  }
}
