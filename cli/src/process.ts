import { spawn } from "node:child_process";

export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  missing: boolean;
}

export interface CommandOptions { cwd?: string; env?: NodeJS.ProcessEnv; unsetEnv?: string[]; timeoutMs?: number; maxOutputBytes?: number }

export async function runCommand(
  command: string,
  args: string[],
  options: CommandOptions = {},
): Promise<CommandResult> {
  const started = Date.now();
  return await new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let outputExceeded = false;
    let timedOut = false;
    let outputBytes = 0;
    let killTimer: NodeJS.Timeout | null = null;
    const maxOutputBytes = options.maxOutputBytes ?? 50 * 1024 * 1024;
    const env = { ...process.env, ...options.env };
    for (const name of options.unsetEnv ?? []) delete env[name];
    const child = spawn(command, args, {
      cwd: options.cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
    });

    const terminate = () => {
      child.kill("SIGTERM");
      if (!killTimer) {
        killTimer = setTimeout(() => child.kill("SIGKILL"), 1_000);
        killTimer.unref();
      }
    };

    const finish = (result: Omit<CommandResult, "duration_ms">) => {
      if (settled) return;
      settled = true;
      resolve({ ...result, duration_ms: Date.now() - started });
    };

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    const append = (stream: "stdout" | "stderr", chunk: string) => {
      if (outputExceeded) return;
      const chunkBytes = Buffer.byteLength(chunk, "utf8");
      if (outputBytes + chunkBytes > maxOutputBytes) {
        outputExceeded = true;
        stderr += `\nCommand output exceeded ${maxOutputBytes} bytes`;
        terminate();
        return;
      }
      outputBytes += chunkBytes;
      if (stream === "stdout") stdout += chunk;
      else stderr += chunk;
    };
    child.stdout.on("data", (chunk: string) => append("stdout", chunk));
    child.stderr.on("data", (chunk: string) => append("stderr", chunk));
    child.on("error", (error: NodeJS.ErrnoException) => {
      finish({ code: 127, stdout, stderr: `${stderr}${error.message}`, missing: error.code === "ENOENT" });
    });
    child.on("close", (code) => finish({ code: outputExceeded || timedOut ? 2 : code ?? 2, stdout, stderr, missing: false }));

    const timeout = options.timeoutMs ?? 10 * 60_000;
    const timer = setTimeout(() => {
      timedOut = true;
      terminate();
      stderr += `\nCommand timed out after ${timeout}ms`;
    }, timeout);
    timer.unref();
    child.on("close", () => {
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
    });
  });
}

export async function commandVersion(
  command: string,
  args: string[] = ["--version"],
  options: Pick<CommandOptions, "env" | "timeoutMs"> = {},
): Promise<string | null> {
  const result = await runCommand(command, args, { timeoutMs: options.timeoutMs ?? 15_000, ...options });
  if (result.missing) return null;
  const lines = `${result.stdout}\n${result.stderr}`.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const versionLine = lines.find((line) => /^(?:[a-z][a-z0-9._-]*\s+)?v?\d+\.\d+(?:\.\d+)?(?:[-+][a-z0-9._-]+)?$/i.test(line));
  if (versionLine) return versionLine;
  return result.code === 0 ? lines[0] ?? null : null;
}
