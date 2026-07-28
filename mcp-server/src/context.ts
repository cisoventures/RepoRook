import { constants } from "node:fs";
import { lstat, open, realpath, stat } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { assertFindingsReportConsistency, parseFindingsReport } from "reporook/report-validation";
import type { Finding, ScanReport } from "reporook/schema";

const maximumReportBytes = 10 * 1024 * 1024;
const maximumSourceBytes = 1024 * 1024;

export type FindingRecord = Finding;

interface RepositoryFile { root: string; file: string }

async function repositoryFile(target: string, requested: string, label: string): Promise<RepositoryFile> {
  const root = await realpath(resolve(target));
  if (!(await stat(root)).isDirectory()) throw new Error("Repository path must be a directory");
  const file = isAbsolute(requested) ? resolve(requested) : resolve(root, requested);
  const traversal = relative(root, file);
  if (traversal === ".." || traversal.startsWith(`..${sep}`) || isAbsolute(traversal)) {
    throw new Error(`${label} resolves outside the repository`);
  }
  let current = root;
  for (const segment of traversal.split(sep).filter(Boolean)) {
    current = join(current, segment);
    const metadata = await lstat(current);
    if (metadata.isSymbolicLink()) throw new Error(`${label} path contains a symbolic link`);
  }
  return { root, file };
}

async function boundedText(source: RepositoryFile, label: string, maximumBytes: number): Promise<string> {
  const before = await lstat(source.file);
  if (before.isSymbolicLink()) throw new Error(`${label} must not be a symbolic link`);
  if (!before.isFile()) throw new Error(`${label} must be a regular file`);
  if (before.size > maximumBytes) throw new Error(`${label} exceeds its ${maximumBytes / (1024 * 1024)} MiB limit`);
  const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
  const handle = await open(source.file, constants.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat();
    if (!opened.isFile()) throw new Error(`${label} must be a regular file`);
    if (opened.size > maximumBytes) throw new Error(`${label} exceeds its ${maximumBytes / (1024 * 1024)} MiB limit`);
    const canonical = await realpath(source.file);
    const traversal = relative(source.root, canonical);
    if (traversal === ".." || traversal.startsWith(`..${sep}`) || isAbsolute(traversal)) throw new Error(`${label} resolves outside the repository`);
    const canonicalMetadata = await stat(canonical);
    if (opened.dev !== canonicalMetadata.dev || opened.ino !== canonicalMetadata.ino) throw new Error(`${label} changed while it was being opened`);
    const chunks: Buffer[] = [];
    let total = 0;
    while (total <= maximumBytes) {
      const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes + 1 - total));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      chunks.push(buffer.subarray(0, bytesRead));
      total += bytesRead;
    }
    if (total > maximumBytes) throw new Error(`${label} exceeds its ${maximumBytes / (1024 * 1024)} MiB limit`);
    try { return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total)); }
    catch { throw new Error(`${label} must contain valid UTF-8 text`); }
  } finally {
    await handle.close();
  }
}

export async function readReport(target: string, requested: string): Promise<ScanReport> {
  const source = await repositoryFile(target, requested, "Findings artifact");
  const report = parseFindingsReport(JSON.parse(await boundedText(source, "Findings artifact", maximumReportBytes)) as unknown);
  const claimedRoot = await realpath(resolve(report.target.path)).catch(() => null);
  if (claimedRoot !== source.root) throw new Error("Findings report is bound to a different repository target");
  assertFindingsReportConsistency(report);
  return report;
}

export function findings(report: ScanReport): FindingRecord[] {
  return report.findings;
}

export function findFinding(report: ScanReport, id: string): FindingRecord {
  const finding = findings(report).find((candidate) => candidate.id === id);
  if (!finding) throw new Error(`Finding not found: ${id}`);
  return finding;
}

export async function codeContext(target: string, finding: FindingRecord, radius = 8): Promise<{ start_line: number; end_line: number; code: string }> {
  const file = await repositoryFile(target, finding.file, "Finding path");
  const source = await boundedText(file, "Finding source", maximumSourceBytes);
  const lines = source.split(/\r?\n/);
  const start = Math.max(1, Number(finding.line || 1) - radius);
  const end = Math.min(lines.length, Number(finding.line || 1) + radius);
  const selected = lines.slice(start - 1, end).map((line, index) => `${String(start + index).padStart(5, " ")} | ${line}`).join("\n");
  return { start_line: start, end_line: end, code: selected };
}

export async function findingContext(target: string, finding: FindingRecord, radius = 8): Promise<{ start_line: number; end_line: number; code: string } | null> {
  if (finding.scanner === "gitleaks") return null;
  const targetKind = finding.metadata?.target_kind;
  if (targetKind === "container-image" || targetKind === "git-history") return null;
  return await codeContext(target, finding, radius);
}
