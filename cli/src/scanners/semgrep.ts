import { access, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { findingFingerprint } from "../fingerprint.js";
import { plainSummary } from "../knowledge.js";
import { repoRelative } from "../path-utils.js";
import { runCommand } from "../process.js";
import { normalizeSeverity } from "../severity.js";
import type { Finding, ScannerAdapter, ScannerContext, ScannerResult } from "../types.js";
import { array, errored, jsonFromOutput, record, scannerParseError, scannerVersion, strings, successful, text, unavailable } from "./shared.js";

const codeExtensions = new Set([".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".java", ".rb", ".php", ".cs", ".rs", ".kt", ".swift"]);
const trustStoreCandidates = [
  "/etc/ssl/certs/ca-certificates.crt",
  "/etc/ssl/cert.pem",
  "/etc/pki/tls/certs/ca-bundle.crt",
];

async function trustStoreEnvironment(): Promise<NodeJS.ProcessEnv> {
  if (process.env.SSL_CERT_FILE || process.env.SSL_CERT_DIR) return {};
  for (const candidate of trustStoreCandidates) {
    try {
      await access(candidate);
      return { SSL_CERT_FILE: candidate };
    } catch {
      // Try the next conventional operating-system trust store.
    }
  }
  return {};
}

async function containsCode(directory: string, depth = 0): Promise<boolean> {
  if (depth > 4) return false;
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); } catch { return false; }
  for (const entry of entries) {
    if (["node_modules", ".git", "dist", "build", ".reporook"].includes(entry.name)) continue;
    if (entry.isFile() && codeExtensions.has(entry.name.slice(entry.name.lastIndexOf(".")))) return true;
    if (entry.isDirectory() && await containsCode(join(directory, entry.name), depth + 1)) return true;
  }
  return false;
}

export function parseSemgrep(raw: unknown, target: string): Finding[] {
  const root = record(raw);
  return array(root.results).map((item) => {
    const result = record(item);
    const extra = record(result.extra);
    const metadata = record(extra.metadata);
    const start = record(result.start);
    const end = record(result.end);
    const rule = text(result.check_id, "semgrep.unknown");
    const file = repoRelative(target, text(result.path));
    const stableEvidence = text(extra.lines) || text(extra.message);
    const ids = findingFingerprint(["semgrep", rule, file, stableEvidence]);
    const cwe = strings(metadata.cwe).map((value) => value.match(/CWE-\d+/i)?.[0]?.toUpperCase() ?? value);
    const references = [...strings(metadata.references), ...strings(metadata.source)].filter((value, index, all) => all.indexOf(value) === index);
    return {
      ...ids,
      scanner: "semgrep",
      rule,
      severity: normalizeSeverity(extra.severity),
      file,
      line: Number(start.line ?? 1),
      end_line: Number(end.line ?? start.line ?? 1),
      column: Number(start.col ?? 1),
      plain_summary: plainSummary({ scanner: "semgrep", rule, cwes: cwe, description: text(extra.message) }),
      description: text(extra.message, `Semgrep rule ${rule} matched.`),
      remediation_hint: text(metadata.fix, text(metadata.remediation, "Review the matched data flow and apply the rule's recommended secure pattern.")),
      references,
      metadata: {
        cwe,
        cve: strings(metadata.cve),
        package: null,
        raw_severity: text(extra.severity) || null,
        confidence: text(metadata.confidence) || null,
        tags: strings(metadata.technology),
      },
    } satisfies Finding;
  });
}

export function semgrepErrors(raw: unknown): string[] {
  const root = record(raw);
  return array(root.errors).map((item) => {
    const error = record(item);
    return text(error.message, text(error.type, "Semgrep reported an unspecified scan error"));
  });
}

export class SemgrepScanner implements ScannerAdapter {
  name = "semgrep";

  async isApplicable(target: string) {
    try { await access(target); } catch { return { applicable: false, reason: "target does not exist" }; }
    return (await containsCode(target)) ? { applicable: true } : { applicable: false, reason: "no supported source files detected" };
  }

  async run(context: ScannerContext): Promise<ScannerResult> {
    const started = Date.now();
    const temporary = await mkdtemp(join(tmpdir(), "reporook-semgrep-"));
    const env = {
      ...await trustStoreEnvironment(),
      XDG_CACHE_HOME: temporary,
      XDG_CONFIG_HOME: temporary,
      SEMGREP_LOG_FILE: join(temporary, "semgrep.log"),
      SEMGREP_SETTINGS_FILE: join(temporary, "settings.yml"),
    };
    try {
      const version = await scannerVersion("semgrep", { env, timeoutMs: 60_000 }, ["--version", "--disable-version-check"]);
      if (!version) return unavailable(this.name, Date.now() - started, "semgrep is not installed or could not start; run `reporook setup`");
      const args = [
        "scan",
        "--json",
        "--config",
        context.config.semgrepConfig,
        "--metrics",
        "off",
        "--disable-version-check",
      ];
      for (const ignored of context.config.ignore) args.push("--exclude", ignored);
      args.push(context.target);
      const result = await runCommand("semgrep", args, { cwd: context.target, env });
      if (result.missing) return unavailable(this.name, result.duration_ms, "semgrep is not installed");
      try {
        const raw = jsonFromOutput(result.stdout, result.stderr);
        const findings = parseSemgrep(raw, context.target);
        const errors = semgrepErrors(raw);
        if (result.code !== 0 || errors.length) {
          const reason = errors.slice(0, 3).join("; ") || result.stderr.trim() || `semgrep exited ${result.code}`;
          const failed = errored(this.name, version, result.duration_ms, reason);
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
