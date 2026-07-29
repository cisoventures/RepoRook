#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { detectGitHubRepository, GitHubAppIntegration } from "./github-app.js";
import { GitHubPublisher } from "./github.js";
import { startDashboardServer } from "./server.js";

const VERSION = "0.9.2";
const help = `RepoRook Service ${VERSION}

Usage:
  reporook-service [--repo PATH] [--port PORT] [--github-repo OWNER/REPO]

Options:
  --repo PATH   Repository to manage (default: current directory)
  --port PORT   Loopback port (default: 7377; use 0 for an ephemeral port)
  --github-repo OWNER/REPO
                Override the repository detected from the github.com origin
  --version     Print the service version
  --help        Show this help

The service binds only to 127.0.0.1 and prints a private dashboard URL. It never
modifies local application code. Optional GitHub publishing accepts only an App
installation restricted to the detected repository and creates a draft PR from
an exact approved proposal. A legacy installation token may be supplied through
REPOROOK_GITHUB_TOKEN; personal access tokens are rejected.
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
  const githubRepository = value(args, "--github-repo") ?? await detectGitHubRepository(repository).catch(() => undefined);
  const githubToken = process.env.REPOROOK_GITHUB_TOKEN;
  if (githubToken && !githubRepository) throw new Error("REPOROOK_GITHUB_TOKEN is set but no github.com repository was detected; provide --github-repo OWNER/REPOSITORY");
  const publisher = githubRepository && githubToken ? new GitHubPublisher({ repository: githubRepository, token: githubToken }) : undefined;
  const githubApp = githubRepository && !githubToken ? await GitHubAppIntegration.open({ repository: githubRepository }) : undefined;
  const dashboard = await startDashboardServer({ repository, port: Number(rawPort), ...(publisher ? { publisher } : {}), ...(githubApp ? { githubApp } : {}) });
  process.stdout.write(`RepoRook dashboard\nRepository: ${repository}\nGitHub target: ${githubRepository ?? "not detected"}\nPrivate URL: ${dashboard.bootstrap_url}\n\nKeep this URL private; it authorizes local dashboard access. Press Ctrl+C to stop.\n`);
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
export { detectGitHubRepository, GitHubAppIntegration, parseGitHubRemote } from "./github-app.js";
export { GitHubPublisher } from "./github.js";
export type { PublishedPullRequest, RemediationPublication, RemediationPublisher } from "./github.js";
