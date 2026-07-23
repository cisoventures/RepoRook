import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { toSarif } from "./sarif.js";
import type { ScanReport } from "./types.js";

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

export async function writeArtifacts(
  target: string,
  report: ScanReport,
  options: { output?: string; sarifOutput?: string; writeSarif?: boolean } = {},
): Promise<{ findingsPath: string; sarifPath: string | null; receiptPath: string }> {
  const outputDir = resolve(target, options.output ?? ".reporook/findings.json");
  const sarifPath = options.writeSarif === false ? null : resolve(target, options.sarifOutput ?? ".reporook/results.sarif");
  const receiptPath = resolve(dirname(outputDir), "scan-receipt.json");
  await writeJson(outputDir, report);
  await writeJson(receiptPath, report.scan_receipt);
  if (sarifPath) await writeJson(sarifPath, toSarif(report));
  return { findingsPath: outputDir, sarifPath, receiptPath };
}
