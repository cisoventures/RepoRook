import { constants, chmodSync, closeSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";

function metadata(path: string): ReturnType<typeof lstatSync> | null {
  try { return lstatSync(path); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

function realDirectory(requested: string, label: string): string {
  const missing: string[] = [];
  let existingPath = requested;
  let existing = metadata(existingPath);
  while (!existing) {
    const parent = dirname(existingPath);
    if (parent === existingPath) throw new Error(`${label} has no usable directory ancestor`);
    missing.unshift(basename(existingPath));
    existingPath = parent;
    existing = metadata(existingPath);
  }
  if (!existing.isDirectory() || existing.isSymbolicLink()) {
    throw new Error(`${label} must be a real non-link directory`);
  }
  let canonical = realpathSync.native(existingPath);
  for (const segment of missing) {
    canonical = join(canonical, segment);
    try { mkdirSync(canonical, { mode: 0o700 }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    const created = lstatSync(canonical);
    if (!created.isDirectory() || created.isSymbolicLink()) {
      throw new Error(`${label} must be a real non-link directory`);
    }
    canonical = realpathSync.native(canonical);
  }
  return canonical;
}

function cacheBase(): string {
  const configuredValue = process.env.XDG_CACHE_HOME;
  const configured = configuredValue ? configuredValue : undefined;
  if (configured !== undefined && !isAbsolute(configured)) {
    throw new Error("XDG_CACHE_HOME must be an absolute path for RepoRook key storage");
  }
  const requested = configured === undefined
    ? join(realpathSync.native(resolve(homedir())), ".cache")
    : resolve(configured);
  return realDirectory(requested, "RepoRook key-store base");
}

export function loadHostLocalKey(fileName: string, label: string): Buffer {
  if (!/^[a-z0-9-]{1,64}$/.test(fileName)) throw new Error("RepoRook key-store file name is invalid");
  const base = cacheBase();
  const directory = realDirectory(join(base, "reporook"), `RepoRook ${label} directory`);
  const directoryMetadata = lstatSync(directory);
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
    throw new Error(`RepoRook ${label} directory is invalid`);
  }
  if (process.platform !== "win32") chmodSync(directory, 0o700);

  const path = join(realpathSync.native(directory), fileName);
  try { writeFileSync(path, randomBytes(32), { mode: 0o600, flag: "wx" }); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }

  const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
  const descriptor = openSync(path, constants.O_RDONLY | noFollow);
  try {
    const opened = fstatSync(descriptor);
    const named = lstatSync(path);
    const unsafePermissions = process.platform !== "win32" && (opened.mode & 0o077) !== 0;
    if (!opened.isFile() || !named.isFile() || named.isSymbolicLink() || opened.size !== 32 || unsafePermissions
      || opened.dev !== named.dev || opened.ino !== named.ino) {
      throw new Error(`RepoRook ${label} key is invalid or has unsafe permissions`);
    }
    const key = readFileSync(descriptor);
    if (key.byteLength !== 32) throw new Error(`RepoRook ${label} key is invalid`);
    return key;
  } finally {
    closeSync(descriptor);
  }
}
