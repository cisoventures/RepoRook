import { spawn } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

export interface CliResult { code: number; stdout: string; stderr: string; }

function resolveCli(): { command: string; prefix: string[] } {
  const override = process.env.REPOROOK_CLI;
  if (override) return { command: override, prefix: [] };
  try {
    return { command: process.execPath, prefix: [require.resolve("reporook")] };
  } catch {
    return { command: "reporook", prefix: [] };
  }
}

export async function runRepoRook(args: string[]): Promise<CliResult> {
  const cli = resolveCli();
  return await new Promise((resolve, reject) => {
    const child = spawn(cli.command, [...cli.prefix, ...args], { stdio: ["ignore", "pipe", "pipe"], shell: false });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 2, stdout, stderr }));
  });
}

export async function scanViaCli(
  path: string,
  extra: string[] = [],
  options: { acceptIncompleteReport?: boolean } = {},
): Promise<Record<string, unknown>> {
  const result = await runRepoRook(["scan", path, "--format", "json", ...extra]);
  let report: Record<string, unknown>;
  try { report = JSON.parse(result.stdout) as Record<string, unknown>; }
  catch {
    if (result.code === 2) throw new Error(result.stderr.trim() || "RepoRook could not complete the scan");
    throw new Error(`RepoRook returned invalid JSON: ${result.stderr.trim()}`);
  }
  if (result.code === 2 && !options.acceptIncompleteReport) {
    throw new Error(result.stderr.trim() || "RepoRook could not complete the scan");
  }
  return report;
}

export async function verifyViaCli(path: string, findingId: string, previousReportPath: string, requireScanners = false): Promise<Record<string, unknown>> {
  const result = await runRepoRook(["verify", findingId, path, "--input", previousReportPath, "--format", "json", ...(requireScanners ? ["--require-scanners"] : [])]);
  try { return JSON.parse(result.stdout) as Record<string, unknown>; }
  catch {
    throw new Error(result.stderr.trim() || "RepoRook could not produce a verification receipt");
  }
}

function jsonResult(result: CliResult, label: string): Record<string, unknown> {
  try { return JSON.parse(result.stdout) as Record<string, unknown>; }
  catch { throw new Error(result.stderr.trim() || `RepoRook could not produce ${label}`); }
}

export async function prioritizeViaCli(path: string, reportPath: string): Promise<Record<string, unknown>> {
  const result = await runRepoRook(["prioritize", path, "--input", reportPath, "--format", "json"]);
  if (result.code !== 0) throw new Error(result.stderr.trim() || "RepoRook could not prioritize the findings");
  return jsonResult(result, "a priority report");
}

export async function remediationPlanViaCli(path: string, findingId: string, reportPath: string): Promise<Record<string, unknown>> {
  const result = await runRepoRook(["plan", findingId, path, "--input", reportPath, "--format", "json"]);
  if (result.code !== 0) throw new Error(result.stderr.trim() || "RepoRook could not prepare the remediation plan");
  return jsonResult(result, "a remediation plan");
}
