import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const contractPath = resolve(root, "contracts/security-review.json");
const contract = JSON.parse(await readFile(contractPath, "utf8"));
const arguments_ = process.argv.slice(2);
const planOnly = arguments_.includes("--plan");

if (arguments_.some((argument) => !["--plan"].includes(argument))) {
  throw new Error("Usage: npm run review:baseline [-- --plan]");
}

const commandPlan = contract.commands.map((command) => ({
  id: command.id,
  command: command.command,
  args: command.args,
  environment: { ...contract.environment, ...command.environment },
  purpose: command.purpose,
}));

if (planOnly) {
  process.stdout.write(`${JSON.stringify({ claims: contract.claims, output: contract.output, commands: commandPlan }, null, 2)}\n`);
  process.exit(0);
}

function git(args, options = {}) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8", ...options });
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function repositoryPath(path) {
  const target = resolve(root, path);
  const traversal = relative(root, target);
  if (traversal === ".." || traversal.startsWith(`..${sep}`)) throw new Error(`Review path escapes the repository: ${path}`);
  return target;
}

async function requireSafeOutput(path) {
  const target = repositoryPath(path);
  const parent = dirname(target);
  const parentTraversal = relative(root, parent).split(sep).filter(Boolean);
  let current = root;
  for (const segment of parentTraversal) {
    current = resolve(current, segment);
    try {
      const metadata = await lstat(current);
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error(`Review output parent is not a regular directory: ${relative(root, current)}`);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      await mkdir(current);
    }
  }
  try {
    const metadata = await lstat(target);
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error(`Review output is not a regular file: ${path}`);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  return target;
}

const tracked = git(["ls-files", "-z", "--", ...contract.integrity_paths])
  .split("\0")
  .filter(Boolean)
  .sort();
if (!tracked.length) throw new Error("The security-review integrity scope did not resolve any tracked files");
const untracked = git(["ls-files", "-z", "--others", "--exclude-standard", "--", ...contract.integrity_paths])
  .split("\0")
  .filter(Boolean)
  .sort();
const trackedSet = new Set(tracked);
const scopedFiles = [...new Set([...tracked, ...untracked])].sort();

const files = [];
for (const path of scopedFiles) {
  const target = repositoryPath(path);
  const metadata = await lstat(target);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error(`Integrity input is not a regular file: ${path}`);
  files.push({ path, source: trackedSet.has(path) ? "tracked" : "untracked", sha256: sha256(await readFile(target)) });
}
const integrityDigest = sha256(files.map((file) => `${file.path}\0${file.sha256}\n`).join(""));
const dirtyPaths = git(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
  .split("\0")
  .filter(Boolean)
  .map((entry) => entry.slice(3))
  .sort();

const report = {
  schema_version: contract.schema_version,
  generated_at: new Date().toISOString(),
  revision: git(["rev-parse", "HEAD"]).trim(),
  dirty: dirtyPaths.length > 0,
  dirty_paths: dirtyPaths,
  platform: {
    os: process.platform,
    arch: process.arch,
    node: process.version,
  },
  safety: {
    ...contract.claims,
    ephemeral_npm_cache: true,
  },
  integrity: {
    algorithm: "sha256",
    digest: integrityDigest,
    tracked_file_count: tracked.length,
    untracked_file_count: untracked.length,
    file_count: files.length,
    files,
  },
  commands: [],
  summary: { passed: 0, failed: 0 },
};

const output = await requireSafeOutput(contract.output);
const npmCache = await mkdtemp(join(tmpdir(), "reporook-review-npm-cache-"));
try {
  for (const command of commandPlan) {
    const started = Date.now();
    const executable = process.platform === "win32" && command.command === "npm" ? "npm.cmd" : command.command;
    process.stdout.write(`\n[security-review] ${command.id}: ${command.command} ${command.args.join(" ")}\n`);
    const result = spawnSync(executable, command.args, {
      cwd: root,
      env: { ...process.env, ...command.environment, npm_config_cache: npmCache },
      stdio: "inherit",
    });
    const passed = result.status === 0;
    report.commands.push({
      id: command.id,
      command: command.command,
      args: command.args,
      purpose: command.purpose,
      passed,
      exit_code: result.status,
      signal: result.signal,
      duration_ms: Date.now() - started,
    });
    report.summary[passed ? "passed" : "failed"] += 1;
  }
} finally {
  await rm(npmCache, { recursive: true, force: true });
}

await writeFile(output, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
await chmod(output, 0o600);
process.stdout.write(`\nSecurity-review baseline evidence written to ${contract.output}.\n`);
process.stdout.write("This evidence is not an independent review or a security opinion.\n");
if (report.summary.failed > 0) process.exitCode = 1;
