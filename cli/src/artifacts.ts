import { mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { renderAgentPrompt } from "./render.js";
import { toSarif } from "./sarif.js";
import type { ScanReport, VerificationReport } from "./types.js";

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

async function writeText(path: string, value: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${value.trimEnd()}\n`, { encoding: "utf8", mode: 0o600 });
}

export function artifactPath(target: string, output: string): string {
  const root = resolve(target);
  const path = resolve(root, output);
  const traversal = relative(root, path);
  if (traversal === ".." || traversal.startsWith(`..${sep}`) || isAbsolute(traversal)) {
    throw new Error("Artifact path resolves outside the repository");
  }
  return path;
}

export async function writeArtifacts(
  target: string,
  report: ScanReport,
  options: { output?: string; sarifOutput?: string; writeSarif?: boolean } = {},
): Promise<{ findingsPath: string; sarifPath: string | null; receiptPath: string; promptPath: string }> {
  const outputDir = artifactPath(target, options.output ?? ".reporook/findings.json");
  const sarifPath = options.writeSarif === false ? null : artifactPath(target, options.sarifOutput ?? ".reporook/results.sarif");
  const receiptPath = resolve(dirname(outputDir), "scan-receipt.json");
  const promptPath = resolve(dirname(outputDir), "agent-prompt.txt");
  const findingsReference = options.output ?? ".reporook/findings.json";
  await writeJson(outputDir, report);
  await writeJson(receiptPath, report.scan_receipt);
  await writeText(promptPath, renderAgentPrompt(report, findingsReference));
  if (sarifPath) await writeJson(sarifPath, toSarif(report));
  return { findingsPath: outputDir, sarifPath, receiptPath, promptPath };
}

export async function writeVerificationArtifact(target: string, report: VerificationReport, output: string): Promise<string> {
  const path = artifactPath(target, output);
  await writeJson(path, report);
  return path;
}
