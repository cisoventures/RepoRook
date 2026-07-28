import { spawn } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

export interface CliResult { code: number; stdout: string; stderr: string; }
export interface CliOptions { maxOutputBytes?: number; timeoutMs?: number; }

function resolveCli(): { command: string; prefix: string[] } {
  const override = process.env.REPOROOK_CLI;
  if (override) {
    if (/\.(?:c|m)?js$/i.test(override)) return { command: process.execPath, prefix: [override] };
    return { command: override, prefix: [] };
  }
  try {
    return { command: process.execPath, prefix: [require.resolve("reporook")] };
  } catch {
    return { command: "reporook", prefix: [] };
  }
}

export async function runRepoRook(args: string[], options: CliOptions = {}): Promise<CliResult> {
  const cli = resolveCli();
  return await new Promise((resolve, reject) => {
    const child = spawn(cli.command, [...cli.prefix, ...args], { stdio: ["ignore", "pipe", "pipe"], shell: false });
    let stdout = "";
    let stderr = "";
    let outputBytes = 0;
    let outputExceeded = false;
    let timedOut = false;
    let killTimer: NodeJS.Timeout | null = null;
    const maximum = options.maxOutputBytes ?? 50 * 1024 * 1024;
    const timeoutMs = options.timeoutMs ?? 15 * 60_000;
    const terminate = () => {
      child.kill("SIGTERM");
      if (!killTimer) {
        killTimer = setTimeout(() => child.kill("SIGKILL"), 1_000);
        killTimer.unref();
      }
    };
    const append = (stream: "stdout" | "stderr", chunk: string) => {
      if (outputExceeded) return;
      const bytes = Buffer.byteLength(chunk, "utf8");
      if (outputBytes + bytes > maximum) {
        outputExceeded = true;
        stderr += `\nRepoRook CLI output exceeded ${maximum} bytes`;
        terminate();
        return;
      }
      outputBytes += bytes;
      if (stream === "stdout") stdout += chunk;
      else stderr += chunk;
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => append("stdout", chunk));
    child.stderr.on("data", (chunk: string) => append("stderr", chunk));
    child.on("error", reject);
    const timeout = setTimeout(() => {
      timedOut = true;
      stderr += `\nRepoRook CLI timed out after ${timeoutMs}ms`;
      terminate();
    }, timeoutMs);
    timeout.unref();
    child.on("close", (code) => {
      clearTimeout(timeout);
      if (killTimer) clearTimeout(killTimer);
      resolve({ code: outputExceeded || timedOut ? 2 : code ?? 2, stdout, stderr });
    });
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

export async function baselineViaCli(path: string, reportPath: string, outputPath: string): Promise<Record<string, unknown>> {
  const result = await runRepoRook(["baseline", path, "--input", reportPath, "--output", outputPath, "--format", "json"]);
  if (result.code !== 0) throw new Error(result.stderr.trim() || "RepoRook could not create the findings baseline");
  return jsonResult(result, "a findings baseline");
}

export async function suppressionViaCli(
  path: string,
  findingId: string,
  reportPath: string,
  outputPath: string,
  owner: string,
  reason: string,
  expires: string,
): Promise<Record<string, unknown>> {
  const result = await runRepoRook([
    "suppress", findingId, path,
    "--input", reportPath,
    "--output", outputPath,
    "--owner", owner,
    "--reason", reason,
    "--expires", expires,
    "--format", "json",
  ]);
  if (result.code !== 0) throw new Error(result.stderr.trim() || "RepoRook could not record the suppression");
  return jsonResult(result, "a finding suppression");
}

export async function approvalViaCli(
  path: string,
  findingId: string,
  approvedBy: string,
  reason: string,
  proposalPath?: string,
): Promise<Record<string, unknown>> {
  const result = await runRepoRook([
    "approve", findingId, path,
    "--approved-by", approvedBy,
    "--reason", reason,
    ...(proposalPath ? ["--proposal", proposalPath] : []),
    "--format", "json",
  ]);
  if (result.code !== 0) throw new Error(result.stderr.trim() || "RepoRook could not record the approval receipt");
  return jsonResult(result, "an approval receipt");
}
