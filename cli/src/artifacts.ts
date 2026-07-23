import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { renderAgentPrompt } from "./render.js";
import { toSarif } from "./sarif.js";
import type { ScanReport } from "./types.js";

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

async function writeText(path: string, value: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${value.trimEnd()}\n`, { encoding: "utf8", mode: 0o600 });
}

export async function writeArtifacts(
  target: string,
  report: ScanReport,
  options: { output?: string; sarifOutput?: string; writeSarif?: boolean } = {},
): Promise<{ findingsPath: string; sarifPath: string | null; receiptPath: string; promptPath: string }> {
  const outputDir = resolve(target, options.output ?? ".reporook/findings.json");
  const sarifPath = options.writeSarif === false ? null : resolve(target, options.sarifOutput ?? ".reporook/results.sarif");
  const receiptPath = resolve(dirname(outputDir), "scan-receipt.json");
  const promptPath = resolve(dirname(outputDir), "agent-prompt.txt");
  const findingsReference = options.output ?? ".reporook/findings.json";
  await writeJson(outputDir, report);
  await writeJson(receiptPath, report.scan_receipt);
  await writeText(promptPath, renderAgentPrompt(report, findingsReference));
  if (sarifPath) await writeJson(sarifPath, toSarif(report));
  return { findingsPath: outputDir, sarifPath, receiptPath, promptPath };
}
