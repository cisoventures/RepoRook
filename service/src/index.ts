#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { startDashboardServer } from "./server.js";

const VERSION = "0.7.0";
const help = `RepoRook Service ${VERSION}

Usage:
  reporook-service [--repo PATH] [--port PORT]

Options:
  --repo PATH   Repository to manage (default: current directory)
  --port PORT   Loopback port (default: 7377; use 0 for an ephemeral port)
  --version     Print the service version
  --help        Show this help

The service binds only to 127.0.0.1 and prints a private dashboard URL. It records
RepoRook evidence and approvals but never applies application-code patches.
`;

function value(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) { process.stdout.write(help); return; }
  if (args.includes("--version") || args.includes("-v")) { process.stdout.write(`${VERSION}\n`); return; }
  const repository = resolve(value(args, "--repo") ?? ".");
  const rawPort = value(args, "--port") ?? "7377";
  if (!/^\d{1,5}$/.test(rawPort)) throw new Error("--port must be an integer between 0 and 65535");
  const dashboard = await startDashboardServer({ repository, port: Number(rawPort) });
  process.stdout.write(`RepoRook dashboard\nRepository: ${repository}\nPrivate URL: ${dashboard.bootstrap_url}\n\nKeep this URL private; it authorizes local dashboard access. Press Ctrl+C to stop.\n`);
  const stop = (): void => { void dashboard.close().finally(() => process.exit(0)); };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

function isEntryPoint(): boolean {
  if (!process.argv[1]) return false;
  try { return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href; }
  catch { return false; }
}

if (isEntryPoint()) main().catch((error: Error) => { process.stderr.write(`RepoRook service error: ${error.message}\n`); process.exitCode = 2; });

export { startDashboardServer } from "./server.js";
