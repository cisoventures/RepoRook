import { spawn } from "node:child_process";

export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  missing: boolean;
}

export async function runCommand(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; timeoutMs?: number } = {},
): Promise<CommandResult> {
  const started = Date.now();
  return await new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
    });

    const finish = (result: Omit<CommandResult, "duration_ms">) => {
      if (settled) return;
      settled = true;
      resolve({ ...result, duration_ms: Date.now() - started });
    };

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    child.on("error", (error: NodeJS.ErrnoException) => {
      finish({ code: 127, stdout, stderr: `${stderr}${error.message}`, missing: error.code === "ENOENT" });
    });
    child.on("close", (code) => finish({ code: code ?? 2, stdout, stderr, missing: false }));

    const timeout = options.timeoutMs ?? 10 * 60_000;
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      stderr += `\nCommand timed out after ${timeout}ms`;
    }, timeout);
    timer.unref();
    child.on("close", () => clearTimeout(timer));
  });
}

export async function commandVersion(command: string, args: string[] = ["--version"]): Promise<string | null> {
  const result = await runCommand(command, args, { timeoutMs: 15_000 });
  if (result.missing) return null;
  const lines = `${result.stdout}\n${result.stderr}`.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const versionLine = lines.find((line) => /^(?:[a-z][a-z0-9._-]*\s+)?v?\d+\.\d+(?:\.\d+)?(?:[-+][a-z0-9._-]+)?$/i.test(line));
  if (versionLine) return versionLine;
  return result.code === 0 ? lines[0] ?? null : null;
}
