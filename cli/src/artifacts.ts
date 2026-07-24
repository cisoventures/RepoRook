import { randomBytes } from "node:crypto";
import { existsSync, lstatSync } from "node:fs";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { prioritizeFindings } from "./prioritization.js";
import { renderAgentPrompt, renderRemediationPrompt } from "./render.js";
import { toSarif } from "./sarif.js";
import type { PrioritizationReport, RemediationPlan, ScanReport, VerificationReport } from "./types.js";

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await atomicWrite(path, `${JSON.stringify(value, null, 2)}\n`);
}

async function writeText(path: string, value: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await atomicWrite(path, `${value.trimEnd()}\n`);
}

async function atomicWrite(path: string, value: string): Promise<void> {
  const temporary = join(dirname(path), `.${basename(path)}.reporook-${process.pid}-${randomBytes(6).toString("hex")}.tmp`);
  try {
    await writeFile(temporary, value, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

function rejectSymbolicLinks(root: string, path: string): void {
  const traversal = relative(root, path);
  let current = root;
  for (const segment of traversal.split(sep).filter(Boolean)) {
    current = join(current, segment);
    try {
      if (lstatSync(current).isSymbolicLink()) throw new Error(`Artifact path contains a symbolic link: ${current}`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}

export function artifactPath(target: string, output: string): string {
  const selected = resolve(target);
  let root = selected;
  while (!existsSync(join(root, ".git")) && dirname(root) !== root) root = dirname(root);
  if (!existsSync(join(root, ".git"))) root = selected;
  const path = resolve(selected, output);
  const traversal = relative(root, path);
  if (traversal === ".." || traversal.startsWith(`..${sep}`) || isAbsolute(traversal)) {
    throw new Error("Artifact path resolves outside the repository");
  }
  rejectSymbolicLinks(root, path);
  return path;
}

export async function writeArtifacts(
  target: string,
  report: ScanReport,
  options: { output?: string; sarifOutput?: string; writeSarif?: boolean } = {},
): Promise<{ findingsPath: string; sarifPath: string | null; receiptPath: string; prioritiesPath: string; promptPath: string }> {
  const outputDir = artifactPath(target, options.output ?? ".reporook/findings.json");
  const sarifPath = options.writeSarif === false ? null : artifactPath(target, options.sarifOutput ?? ".reporook/results.sarif");
  const receiptPath = artifactPath(target, resolve(dirname(outputDir), "scan-receipt.json"));
  const prioritiesPath = artifactPath(target, resolve(dirname(outputDir), "priorities.json"));
  const promptPath = artifactPath(target, resolve(dirname(outputDir), "agent-prompt.txt"));
  const selectedPaths = [outputDir, receiptPath, prioritiesPath, promptPath, ...(sarifPath ? [sarifPath] : [])];
  if (new Set(selectedPaths).size !== selectedPaths.length) throw new Error("Scan artifact paths must be distinct");
  const findingsReference = options.output ?? ".reporook/findings.json";
  await writeJson(outputDir, report);
  await writeJson(receiptPath, report.scan_receipt);
  await writeJson(prioritiesPath, prioritizeFindings(report));
  await writeText(promptPath, renderAgentPrompt(report, findingsReference));
  if (sarifPath) await writeJson(sarifPath, toSarif(report));
  return { findingsPath: outputDir, sarifPath, receiptPath, prioritiesPath, promptPath };
}

export async function writePrioritizationArtifact(target: string, report: PrioritizationReport, output: string): Promise<string> {
  const path = artifactPath(target, output);
  await writeJson(path, report);
  return path;
}

export async function writeRemediationArtifacts(
  target: string,
  plan: RemediationPlan,
  options: { planOutput: string; promptOutput: string; findingsReference: string },
): Promise<{ planPath: string; promptPath: string }> {
  const planPath = artifactPath(target, options.planOutput);
  const promptPath = artifactPath(target, options.promptOutput);
  if (planPath === promptPath) throw new Error("Remediation plan and prompt paths must be distinct");
  await writeJson(planPath, plan);
  await writeText(promptPath, renderRemediationPrompt(plan, options.planOutput, options.findingsReference));
  return { planPath, promptPath };
}

export async function writeVerificationArtifact(target: string, report: VerificationReport, output: string): Promise<string> {
  const path = artifactPath(target, output);
  await writeJson(path, report);
  return path;
}
