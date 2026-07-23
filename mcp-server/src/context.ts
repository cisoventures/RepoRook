import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";

export interface FindingRecord extends Record<string, unknown> {
  id: string;
  fingerprint?: string;
  scanner?: string;
  rule?: string;
  file: string;
  line: number;
  description: string;
  remediation_hint: string;
}

export async function readReport(path: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(resolve(path), "utf8")) as Record<string, unknown>;
}

export function findings(report: Record<string, unknown>): FindingRecord[] {
  return Array.isArray(report.findings) ? report.findings as FindingRecord[] : [];
}

export function findFinding(report: Record<string, unknown>, id: string): FindingRecord {
  const finding = findings(report).find((candidate) => candidate.id === id);
  if (!finding) throw new Error(`Finding not found: ${id}`);
  return finding;
}

export async function codeContext(target: string, finding: FindingRecord, radius = 8): Promise<{ start_line: number; end_line: number; code: string }> {
  const root = resolve(target);
  const file = isAbsolute(finding.file) ? resolve(finding.file) : resolve(root, finding.file);
  const traversal = relative(root, file);
  if (traversal.startsWith("..") || isAbsolute(traversal)) throw new Error("Finding path resolves outside the repository");
  const source = await readFile(file, "utf8");
  const lines = source.split(/\r?\n/);
  const start = Math.max(1, Number(finding.line || 1) - radius);
  const end = Math.min(lines.length, Number(finding.line || 1) + radius);
  const selected = lines.slice(start - 1, end).map((line, index) => `${String(start + index).padStart(5, " ")} | ${line}`).join("\n");
  return { start_line: start, end_line: end, code: selected };
}
