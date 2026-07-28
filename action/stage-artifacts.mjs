#!/usr/bin/env node
import { constants } from "node:fs";
import { lstat, mkdir, open, realpath, rm, stat, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

const maximumFileBytes = 50 * 1024 * 1024;
const maximumTotalBytes = 100 * 1024 * 1024;
const artifactNames = ["findings.json", "results.sarif", "scan-receipt.json", "priorities.json", "agent-prompt.txt"];

const source = resolve(process.argv[2] ?? "");
const destination = resolve(process.argv[3] ?? "");
if (!process.argv[2] || !process.argv[3] || source === destination) throw new Error("Usage: stage-artifacts.mjs SOURCE_DIR DESTINATION_DIR");

const sourceRoot = await realpath(source).catch(() => null);
if (!sourceRoot || !(await stat(sourceRoot)).isDirectory()) throw new Error("RepoRook artifact source must be a directory");
await rm(destination, { recursive: true, force: true });
await mkdir(destination, { recursive: true, mode: 0o700 });

let total = 0;
let copied = 0;
for (const name of artifactNames) {
  const input = join(sourceRoot, name);
  const before = await lstat(input).catch(() => null);
  if (!before) continue;
  if (!before.isFile() || before.isSymbolicLink()) throw new Error(`RepoRook artifact must be a regular non-link file: ${name}`);
  if (before.size > maximumFileBytes || total + before.size > maximumTotalBytes) throw new Error("RepoRook artifact staging exceeded its size limit");
  const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
  const handle = await open(input, constants.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size > maximumFileBytes) throw new Error(`RepoRook artifact must be a bounded regular file: ${name}`);
    const canonical = await realpath(input);
    const traversal = relative(sourceRoot, canonical);
    if (traversal === ".." || traversal.startsWith(`..${sep}`) || isAbsolute(traversal)) throw new Error(`RepoRook artifact resolves outside its source directory: ${name}`);
    const canonicalMetadata = await stat(canonical);
    if (opened.dev !== canonicalMetadata.dev || opened.ino !== canonicalMetadata.ino) throw new Error(`RepoRook artifact changed while it was being staged: ${name}`);
    const contents = await handle.readFile();
    if (contents.length !== opened.size) throw new Error(`RepoRook artifact changed size while it was being staged: ${name}`);
    await writeFile(join(destination, name), contents, { flag: "wx", mode: 0o600 });
    total += contents.length;
    copied += 1;
  } finally {
    await handle.close();
  }
}

process.stdout.write(`Staged ${copied} regular RepoRook artifact${copied === 1 ? "" : "s"} (${total} bytes).\n`);
