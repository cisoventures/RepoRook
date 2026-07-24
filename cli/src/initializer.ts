import { randomBytes } from "node:crypto";
import { lstat, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { defaultConfig, scannerNames } from "./config.js";
import type { InitializationResult, ProjectProfile, ProjectStack, RepoRookConfig } from "./types.js";

const skippedDirectories = new Set([".git", ".reporook", ".venv", "build", "coverage", "dist", "node_modules", "target", "vendor", "venv"]);
const configCandidates = ["reporook.yml", "reporook.yaml", ".reporook.yml", ".reporook.json"];
const maxFiles = 10_000;
const maxDepth = 8;

const osvNames = new Set([
  "bun.lock", "bun.lockb", "buildscript-gradle.lockfile", "cabal.project.freeze", "Cargo.lock", "composer.lock", "conan.lock",
  "deps.json", "Gemfile.lock", "gems.locked", "go.mod", "gradle.lockfile", "mix.lock", "osv-scanner-custom.json", "package-lock.json",
  "packages.config", "packages.lock.json", "pdm.lock", "Pipfile.lock", "pnpm-lock.yaml", "poetry.lock", "pom.xml", "pubspec.lock",
  "pylock.toml", "renv.lock", "stack.yaml.lock", "uv.lock", "yarn.lock",
]);
const sourceExtensions = new Set([".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".java", ".rb", ".php", ".cs", ".rs", ".kt", ".swift"]);

interface FileInventory { files: string[]; truncated: boolean }

async function inventory(target: string): Promise<FileInventory> {
  const files: string[] = [];
  let truncated = false;
  const walk = async (directory: string, depth: number): Promise<void> => {
    if (truncated || depth > maxDepth) return;
    const entries = await readdir(directory, { withFileTypes: true }).catch(() => []);
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (files.length >= maxFiles) { truncated = true; return; }
      if (entry.isSymbolicLink()) continue;
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!skippedDirectories.has(entry.name.toLowerCase())) await walk(absolute, depth + 1);
      } else if (entry.isFile()) {
        files.push(relative(target, absolute).replaceAll("\\", "/"));
      }
    }
  };
  await walk(target, 0);
  return { files, truncated };
}

function evidence(files: string[], predicate: (path: string) => boolean): string[] {
  return files.filter(predicate).slice(0, 8);
}

function extension(path: string): string {
  const name = basename(path);
  const dot = name.lastIndexOf(".");
  return dot >= 0 ? name.slice(dot).toLowerCase() : "";
}

function stack(name: string, files: string[], predicate: (path: string) => boolean): ProjectStack | null {
  const matched = evidence(files, predicate);
  return matched.length ? { name, evidence: matched } : null;
}

function isRoot(path: string): boolean { return !path.includes("/"); }
function isRequirement(path: string): boolean { return /^requirements.*\.txt$/i.test(basename(path)); }

export async function detectProject(targetInput: string): Promise<ProjectProfile> {
  const target = resolve(targetInput);
  const stats = await lstat(target).catch(() => null);
  if (!stats?.isDirectory()) throw new Error(`Target is not a directory: ${target}`);
  const found = await inventory(target);
  const stacks = [
    stack("JavaScript / TypeScript", found.files, (path) => ["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "tsconfig.json"].includes(basename(path)) || [".js", ".jsx", ".ts", ".tsx"].includes(extension(path))),
    stack("Python", found.files, (path) => ["pyproject.toml", "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "pylock.toml"].includes(basename(path)) || isRequirement(path) || extension(path) === ".py"),
    stack("Go", found.files, (path) => ["go.mod", "go.sum"].includes(basename(path)) || extension(path) === ".go"),
    stack("Rust", found.files, (path) => ["Cargo.toml", "Cargo.lock"].includes(basename(path)) || extension(path) === ".rs"),
    stack("Java / Kotlin", found.files, (path) => ["pom.xml", "gradle.lockfile", "build.gradle", "build.gradle.kts"].includes(basename(path)) || [".java", ".kt"].includes(extension(path))),
    stack("Ruby", found.files, (path) => ["Gemfile", "Gemfile.lock", "gems.locked"].includes(basename(path)) || extension(path) === ".rb"),
    stack("PHP", found.files, (path) => ["composer.json", "composer.lock"].includes(basename(path)) || extension(path) === ".php"),
    stack(".NET", found.files, (path) => ["packages.config", "packages.lock.json", "deps.json"].includes(basename(path)) || [".cs", ".csproj", ".fsproj"].includes(extension(path))),
    stack("Dart", found.files, (path) => ["pubspec.yaml", "pubspec.lock"].includes(basename(path)) || extension(path) === ".dart"),
    stack("Elixir", found.files, (path) => ["mix.exs", "mix.lock"].includes(basename(path)) || [".ex", ".exs"].includes(extension(path))),
    stack("R", found.files, (path) => basename(path) === "renv.lock" || [".r", ".rmd"].includes(extension(path))),
    stack("Haskell", found.files, (path) => ["stack.yaml", "stack.yaml.lock", "cabal.project.freeze"].includes(basename(path)) || extension(path) === ".hs"),
    stack("C / C++", found.files, (path) => ["conan.lock", "vcpkg.json"].includes(basename(path)) || [".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"].includes(extension(path))),
  ].filter((value): value is ProjectStack => value !== null);

  const rootPackageLock = found.files.some((path) => path === "package-lock.json");
  const rootPython = found.files.some((path) => isRoot(path) && (isRequirement(path) || ["poetry.lock", "uv.lock"].includes(basename(path))));
  const osv = found.files.some((path) => {
    const name = basename(path);
    const supported = osvNames.has(name) || isRequirement(path) || path.toLowerCase().endsWith("gradle/verification-metadata.xml");
    return supported && !(isRoot(path) && (name === "package-lock.json" || name === "poetry.lock" || name === "uv.lock" || isRequirement(path)));
  });
  const code = found.files.some((path) => sourceExtensions.has(extension(path)));
  const recommended = new Set<string>(["gitleaks"]);
  if (code) recommended.add("semgrep");
  if (rootPackageLock) recommended.add("npm-audit");
  if (rootPython) recommended.add("pip-audit");
  if (osv) recommended.add("osv-scanner");
  return {
    target,
    stacks,
    recommended_scanners: scannerNames.filter((name) => recommended.has(name)),
    evidence_truncated: found.truncated,
  };
}

function yaml(config: RepoRookConfig): string {
  return [
    "# Generated by `reporook init`. Review scanner setup with `reporook doctor`.",
    `failOn: ${config.failOn}`,
    `outputDir: ${config.outputDir}`,
    `semgrepConfig: ${config.semgrepConfig}`,
    "paths:",
    ...config.paths.map((path) => `  - ${path}`),
    "ignore:",
    ...config.ignore.map((path) => `  - ${path}`),
    ...(config.requiredScanners.length
      ? ["requiredScanners:", ...config.requiredScanners.map((name) => `  - ${name}`)]
      : ["requiredScanners: []"]),
    "scanners:",
    ...scannerNames.map((name) => `  ${name}: true`),
    "",
  ].join("\n");
}

async function existingConfig(target: string): Promise<string | null> {
  for (const candidate of configCandidates) {
    const path = join(target, candidate);
    const stats = await lstat(path).catch(() => null);
    if (stats) return path;
  }
  return null;
}

async function atomicReplace(path: string, contents: string, mode: number): Promise<void> {
  const temporary = join(dirname(path), `.${basename(path)}.reporook-${process.pid}-${randomBytes(6).toString("hex")}.tmp`);
  try {
    await writeFile(temporary, contents, { encoding: "utf8", mode, flag: "wx" });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

async function updateGitignore(target: string): Promise<boolean> {
  const path = join(target, ".gitignore");
  const stats = await lstat(path).catch(() => null);
  if (stats?.isSymbolicLink()) throw new Error("Refusing to update a symbolic-link .gitignore");
  if (stats && !stats.isFile()) throw new Error(".gitignore exists but is not a regular file");
  const current = stats ? await readFile(path, "utf8") : "";
  if (current.split(/\r?\n/).some((line) => [".reporook", ".reporook/"].includes(line.trim()))) return false;
  const prefix = current && !current.endsWith("\n") ? `${current}\n` : current;
  const contents = `${prefix}${current ? "" : "# RepoRook local evidence\n"}.reporook/\n`;
  if (stats) await atomicReplace(path, contents, stats.mode & 0o777);
  else await writeFile(path, contents, { encoding: "utf8", mode: 0o644, flag: "wx" });
  return true;
}

export async function initializeRepository(targetInput: string, force = false): Promise<InitializationResult> {
  const profile = await detectProject(targetInput);
  const current = await existingConfig(profile.target);
  const configPath = current ?? join(profile.target, "reporook.yml");
  if (current && !force) {
    return {
      target: profile.target,
      config_path: configPath,
      status: "already-configured",
      gitignore_updated: false,
      profile,
      next_commands: ["reporook doctor .", "reporook scan . --require-scanners"],
    };
  }
  const existingStats = await lstat(configPath).catch(() => null);
  if (existingStats?.isSymbolicLink()) throw new Error("Refusing to overwrite a symbolic-link RepoRook configuration");
  if (existingStats && !existingStats.isFile()) throw new Error("RepoRook configuration path is not a regular file");
  const config: RepoRookConfig = {
    ...structuredClone(defaultConfig),
    requiredScanners: [...profile.recommended_scanners],
    scanners: Object.fromEntries(scannerNames.map((name) => [name, true])),
  };
  const contents = configPath.endsWith(".json") ? `${JSON.stringify(config, null, 2)}\n` : yaml(config);
  if (existingStats) await atomicReplace(configPath, contents, existingStats.mode & 0o777);
  else await writeFile(configPath, contents, { encoding: "utf8", mode: 0o600, flag: "wx" });
  const gitignoreUpdated = await updateGitignore(profile.target);
  return {
    target: profile.target,
    config_path: configPath,
    status: existingStats ? "overwritten" : "created",
    gitignore_updated: gitignoreUpdated,
    profile,
    next_commands: ["reporook doctor .", "reporook setup", "reporook scan . --require-scanners"],
  };
}

export function renderInitialization(result: InitializationResult): string {
  const detected = result.profile.stacks.length ? result.profile.stacks.map((item) => item.name).join(", ") : "no supported application stack yet";
  const scanners = result.profile.recommended_scanners.length ? result.profile.recommended_scanners.join(", ") : "none";
  return [
    result.status === "already-configured" ? "RepoRook is already initialized" : "RepoRook initialized",
    `Configuration: ${result.config_path}`,
    `Detected: ${detected}`,
    `Required checks: ${scanners}`,
    result.profile.evidence_truncated ? "Note: project detection stopped after 10,000 files; review the generated configuration." : "Project detection completed.",
    "",
    "Next:",
    ...result.next_commands.map((command) => `  ${command}`),
  ].join("\n");
}
