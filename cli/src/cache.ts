import { randomBytes } from "node:crypto";
import { lstat, mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { artifactPath } from "./artifacts.js";
import { sha256 } from "./fingerprint.js";
import { matchesAny } from "./path-utils.js";
import { runCommand } from "./process.js";
import type { Finding, FindingMetadata, RepoRookConfig, ScannerResult, ScannerStatus, Severity } from "./types.js";
import { VERSION } from "./version.js";

const cacheSchema = "1.0";
const maxCacheBytes = 10 * 1024 * 1024;
const maxCacheFilesPerScanner = 32;
const severities = new Set<Severity>(["critical", "high", "medium", "low"]);

interface CacheRecord {
  schema_version: "1.0";
  key: string;
  scanner: string;
  scanner_version: string;
  created_at: string;
  result: ScannerResult;
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function requiredString(value: unknown, maximum = 100_000): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= maximum ? value : null;
}

function optionalString(value: unknown, maximum = 10_000): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  return typeof value === "string" && value.length <= maximum ? value : undefined;
}

function strings(value: unknown, maximumItems = 1_000): string[] | null {
  if (!Array.isArray(value) || value.length > maximumItems || value.some((item) => typeof item !== "string" || item.length > 10_000)) return null;
  return [...value] as string[];
}

function positiveInteger(value: unknown): number | null {
  return Number.isSafeInteger(value) && Number(value) >= 1 ? Number(value) : null;
}

function cachedMetadata(value: unknown): FindingMetadata | null {
  const input = object(value);
  if (!input) return null;
  const cwe = strings(input.cwe);
  const cve = strings(input.cve);
  const packageName = optionalString(input.package);
  const rawSeverity = optionalString(input.raw_severity);
  if (!cwe || !cve || packageName === undefined || rawSeverity === undefined) return null;
  const metadata: FindingMetadata = { cwe, cve, package: packageName, raw_severity: rawSeverity };
  if (input.installed_version !== undefined) {
    const installedVersion = optionalString(input.installed_version);
    if (installedVersion === undefined) return null;
    metadata.installed_version = installedVersion;
  }
  if (input.fixed_versions !== undefined) {
    const fixed = strings(input.fixed_versions);
    if (!fixed) return null;
    metadata.fixed_versions = fixed;
  }
  if (input.confidence !== undefined) {
    const confidence = optionalString(input.confidence);
    if (confidence === undefined) return null;
    metadata.confidence = confidence;
  }
  if (input.tags !== undefined) {
    const tags = strings(input.tags);
    if (!tags) return null;
    metadata.tags = tags;
  }
  if (input.target_kind !== undefined) {
    if (input.target_kind !== "container-image" && input.target_kind !== "git-history") return null;
    metadata.target_kind = input.target_kind;
  }
  const target = optionalString(input.target);
  if (target !== undefined) {
    if (target === null) return null;
    metadata.target = target;
  }
  const sourceCommit = optionalString(input.source_commit);
  if (sourceCommit !== undefined) {
    if (sourceCommit === null || !/^[a-fA-F0-9]{7,64}$/.test(sourceCommit)) return null;
    metadata.source_commit = sourceCommit;
  }
  return metadata;
}

function cachedFinding(value: unknown, scanner: string): Finding | null {
  const input = object(value);
  if (!input || input.scanner !== scanner || typeof input.severity !== "string" || !severities.has(input.severity as Severity)) return null;
  const id = requiredString(input.id, 15);
  const rule = requiredString(input.rule, 2_000);
  const file = requiredString(input.file, 10_000);
  const plainSummary = requiredString(input.plain_summary, 10_000);
  const description = requiredString(input.description, 100_000);
  const remediationHint = requiredString(input.remediation_hint, 20_000);
  const fingerprint = requiredString(input.fingerprint, 71);
  const line = positiveInteger(input.line);
  const references = strings(input.references);
  const metadata = cachedMetadata(input.metadata);
  if (!id || !/^rr-[a-f0-9]{12}$/.test(id) || !rule || !file || !plainSummary || !description || !remediationHint
    || !fingerprint || !/^sha256:[a-f0-9]{64}$/.test(fingerprint) || !line || !references || !metadata) return null;
  const finding: Finding = {
    id,
    scanner,
    rule,
    severity: input.severity as Severity,
    file,
    line,
    plain_summary: plainSummary,
    description,
    remediation_hint: remediationHint,
    fingerprint,
    references,
    metadata,
  };
  if (input.end_line !== undefined) {
    const endLine = positiveInteger(input.end_line);
    if (!endLine) return null;
    finding.end_line = endLine;
  }
  if (input.column !== undefined) {
    const column = positiveInteger(input.column);
    if (!column) return null;
    finding.column = column;
  }
  return finding;
}

function cachedResult(value: unknown, scanner: string, version: string, ageMs: number): ScannerResult | null {
  const input = object(value);
  const rawStatus = object(input?.status);
  if (!input || !rawStatus || rawStatus.name !== scanner || rawStatus.version !== version || rawStatus.applicable !== true
    || rawStatus.available !== true || rawStatus.status !== "ok" || !Array.isArray(input.findings) || input.findings.length > 100_000) return null;
  const findings: Finding[] = [];
  for (const value of input.findings) {
    const finding = cachedFinding(value, scanner);
    if (!finding) return null;
    findings.push(finding);
  }
  if (Number(rawStatus.finding_count) !== findings.length) return null;
  const originalDuration = Number.isSafeInteger(rawStatus.duration_ms) && Number(rawStatus.duration_ms) >= 0 ? Number(rawStatus.duration_ms) : 0;
  const status: ScannerStatus = {
    name: scanner,
    applicable: true,
    available: true,
    version,
    status: "ok",
    finding_count: findings.length,
    duration_ms: 0,
    reason: `cached successful evidence (${Math.max(0, Math.floor(ageMs / 1_000))}s old; original run ${originalDuration}ms)`,
  };
  return { status, findings };
}

function scannerName(value: string): string {
  if (!/^[a-z0-9-]{1,64}$/.test(value)) throw new Error("Invalid scanner cache name");
  return value;
}

function ignoredLocalPath(pathInput: string, config: RepoRookConfig): boolean {
  const path = pathInput.replaceAll("\\", "/").replace(/\/$/, "");
  if (path === ".reporook" || path.startsWith(".reporook/")) return true;
  return matchesAny(path, config.ignore) || matchesAny(`${path}/__reporook_entry__`, config.ignore);
}

export async function cacheEligible(target: string, commit: string | null, config: RepoRookConfig): Promise<boolean> {
  if (!commit) return false;
  const result = await runCommand("git", ["status", "--porcelain=v1", "-z", "--untracked-files=normal", "--ignored=matching"], { cwd: target, timeoutMs: 30_000 });
  if (result.code !== 0) return false;
  for (const entry of result.stdout.split("\0").filter(Boolean)) {
    if (entry.length < 4) return false;
    const state = entry.slice(0, 2);
    const path = entry.slice(3);
    if ((state === "??" || state === "!!") && ignoredLocalPath(path, config)) continue;
    return false;
  }
  return true;
}

export function scannerCacheKey(input: {
  commit: string;
  scanner: string;
  scannerVersion: string;
  config: RepoRookConfig;
  changedFiles?: string[];
}): string {
  return sha256(JSON.stringify({
    schema_version: cacheSchema,
    reporook_version: VERSION,
    commit: input.commit,
    scanner: scannerName(input.scanner),
    scanner_version: input.scannerVersion,
    config: input.config,
    changed_files: input.changedFiles ? [...input.changedFiles].sort() : null,
  }));
}

function cacheFile(target: string, scanner: string, key: string): string {
  if (!/^[a-f0-9]{64}$/.test(key)) throw new Error("Invalid scanner cache key");
  return artifactPath(target, `.reporook/cache/v1/${scannerName(scanner)}/${key}.json`);
}

export async function readScannerCache(options: {
  target: string;
  scanner: string;
  version: string;
  key: string;
  ttlMs: number;
  now?: Date;
}): Promise<ScannerResult | null> {
  const path = cacheFile(options.target, options.scanner, options.key);
  const metadata = await lstat(path).catch(() => null);
  if (!metadata || !metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maxCacheBytes) return null;
  let value: unknown;
  try { value = JSON.parse(await readFile(path, "utf8")) as unknown; }
  catch { return null; }
  const record = object(value);
  const createdAt = Date.parse(typeof record?.created_at === "string" ? record.created_at : "");
  const ageMs = (options.now ?? new Date()).getTime() - createdAt;
  if (!record || record.schema_version !== cacheSchema || record.key !== options.key || record.scanner !== options.scanner
    || record.scanner_version !== options.version || !Number.isFinite(createdAt) || ageMs < 0 || ageMs > options.ttlMs) return null;
  return cachedResult(record.result, options.scanner, options.version, ageMs);
}

async function prune(directory: string): Promise<void> {
  const files = (await readdir(directory).catch(() => [])).filter((name) => /^[a-f0-9]{64}\.json$/.test(name));
  if (files.length <= maxCacheFilesPerScanner) return;
  const ordered = await Promise.all(files.map(async (name) => ({ name, metadata: await lstat(join(directory, name)).catch(() => null) })));
  ordered.sort((left, right) => (right.metadata?.mtimeMs ?? 0) - (left.metadata?.mtimeMs ?? 0));
  await Promise.all(ordered.slice(maxCacheFilesPerScanner).map(async ({ name, metadata }) => {
    if (metadata?.isFile() && !metadata.isSymbolicLink()) await rm(join(directory, name), { force: true });
  }));
}

export async function writeScannerCache(options: {
  target: string;
  scanner: string;
  version: string;
  key: string;
  result: ScannerResult;
  now?: Date;
}): Promise<void> {
  if (options.result.status.status !== "ok" || options.result.status.version !== options.version) return;
  const path = cacheFile(options.target, options.scanner, options.key);
  const directory = dirname(path);
  const existing = await lstat(path).catch(() => null);
  if (existing && (!existing.isFile() || existing.isSymbolicLink())) return;
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const directoryMetadata = await lstat(directory);
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) return;
  const record: CacheRecord = {
    schema_version: cacheSchema,
    key: options.key,
    scanner: options.scanner,
    scanner_version: options.version,
    created_at: (options.now ?? new Date()).toISOString(),
    result: options.result,
  };
  const contents = `${JSON.stringify(record)}\n`;
  if (Buffer.byteLength(contents, "utf8") > maxCacheBytes) return;
  const temporary = join(directory, `.${basename(path)}.${process.pid}-${randomBytes(6).toString("hex")}.tmp`);
  try {
    await writeFile(temporary, contents, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await rename(temporary, path);
    await prune(directory);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}
