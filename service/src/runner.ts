import { spawn } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const maxOutputBytes = 10 * 1024 * 1024;

export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

export type CliRunner = (args: string[]) => Promise<CliResult>;

function resolveCli(): { command: string; prefix: string[] } {
  const override = process.env.REPOROOK_CLI;
  if (override) return { command: override, prefix: [] };
  try {
    return { command: process.execPath, prefix: [require.resolve("reporook")] };
  } catch {
    return { command: "reporook", prefix: [] };
  }
}

export const runRepoRook: CliRunner = async (args) => {
  const cli = resolveCli();
  return await new Promise((resolve, reject) => {
    const child = spawn(cli.command, [...cli.prefix, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
      env: process.env,
    });
    let stdout = "";
    let stderr = "";
    let outputBytes = 0;
    let settled = false;
    const finish = (result: CliResult): void => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const collect = (stream: "stdout" | "stderr", chunk: Buffer): void => {
      outputBytes += chunk.byteLength;
      if (outputBytes > maxOutputBytes) {
        child.kill("SIGTERM");
        finish({ code: 2, stdout, stderr: "RepoRook produced more than 10 MiB of process output" });
        return;
      }
      if (stream === "stdout") stdout += chunk.toString("utf8");
      else stderr += chunk.toString("utf8");
    };
    child.stdout.on("data", (chunk: Buffer) => collect("stdout", chunk));
    child.stderr.on("data", (chunk: Buffer) => collect("stderr", chunk));
    child.on("error", reject);
    child.on("close", (code) => finish({ code: code ?? 2, stdout, stderr }));
  });
};
