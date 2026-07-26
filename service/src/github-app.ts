import { execFile } from "node:child_process";
import { createHash, randomBytes, sign } from "node:crypto";
import { chmod, lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { GitHubPublisher, type PublishedPullRequest, type RemediationPublication, type RemediationPublisher } from "./github.js";

const githubVersion = "2026-03-10";
const flowLifetimeMs = 15 * 60 * 1_000;
const credentialLimit = 128 * 1_024;
const installationPermissions = { metadata: "read", contents: "write", pull_requests: "write" } as const;

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

interface StoredCredentials {
  schema_version: "1.0";
  repository: string;
  app_id: number;
  app_slug: string;
  installation_id: number;
  private_key: string;
  created_at: string;
}

interface PendingApp {
  app_id: number;
  app_slug: string;
  private_key: string;
}

interface PendingFlow {
  expires_at: number;
  origin: string;
  stage: "manifest" | "installation";
  app?: PendingApp;
}

interface CachedToken {
  value: string;
  expires_at: number;
}

export interface GitHubManifestRequest {
  action: string;
  manifest: string;
}

export interface GitHubAppStatus {
  enabled: boolean;
  connectable: true;
  repository: string;
  mode: "guided-app";
  app: string | null;
}

export interface GitHubAppIntegrationOptions {
  repository: string;
  credentialPath?: string;
  fetch?: FetchLike;
  apiBase?: string;
  githubBase?: string;
  now?: () => Date;
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} returned an invalid response`);
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) throw new Error(`${label} is missing`);
  return value;
}

function safeRepository(value: string): string {
  const repository = value.trim();
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,38})\/[A-Za-z0-9_.-]{1,100}$/.test(repository)) {
    throw new Error("GitHub repository must use the OWNER/REPOSITORY form");
  }
  return repository;
}

function encodedRepository(repository: string): string {
  return repository.split("/").map(encodeURIComponent).join("/");
}

function safeLoopbackOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "http:" || (url.hostname !== "127.0.0.1" && url.hostname !== "[::1]" && url.hostname !== "::1")) {
    throw new Error("GitHub onboarding callbacks must use the loopback dashboard origin");
  }
  return url.origin;
}

function validPrivateKey(value: unknown): string {
  const key = requiredString(value, "GitHub App private key");
  if (Buffer.byteLength(key, "utf8") > 64 * 1_024 || !/^-----BEGIN (?:RSA )?PRIVATE KEY-----\n/.test(key)) {
    throw new Error("GitHub App returned an invalid private key");
  }
  return key;
}

function parseStored(value: unknown, repository: string): StoredCredentials {
  const record = object(value, "Stored GitHub App credentials");
  const appId = Number(record.app_id);
  const installationId = Number(record.installation_id);
  const appSlug = requiredString(record.app_slug, "Stored GitHub App slug");
  const createdAt = requiredString(record.created_at, "Stored GitHub App creation time");
  if (record.schema_version !== "1.0" || record.repository !== repository) throw new Error("Stored GitHub App credentials belong to a different repository");
  if (!Number.isSafeInteger(appId) || appId <= 0 || !Number.isSafeInteger(installationId) || installationId <= 0) {
    throw new Error("Stored GitHub App credentials contain an invalid identifier");
  }
  if (!/^[a-z0-9-]{1,100}$/.test(appSlug) || !Number.isFinite(Date.parse(createdAt))) {
    throw new Error("Stored GitHub App credentials are invalid");
  }
  return {
    schema_version: "1.0",
    repository,
    app_id: appId,
    app_slug: appSlug,
    installation_id: installationId,
    private_key: validPrivateKey(record.private_key),
    created_at: createdAt,
  };
}

function defaultCredentialPath(repository: string): string {
  const digest = createHash("sha256").update(repository.toLowerCase()).digest("hex").slice(0, 20);
  let base: string;
  if (platform() === "win32" && process.env.APPDATA && isAbsolute(process.env.APPDATA)) {
    base = join(process.env.APPDATA, "RepoRook");
  } else if (platform() === "darwin") {
    base = join(homedir(), "Library", "Application Support", "RepoRook");
  } else if (process.env.XDG_CONFIG_HOME && isAbsolute(process.env.XDG_CONFIG_HOME)) {
    base = join(process.env.XDG_CONFIG_HOME, "reporook");
  } else {
    base = join(homedir(), ".config", "reporook");
  }
  return join(base, `github-${digest}.json`);
}

async function secureDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("GitHub credential directory must be a real directory");
  if (platform() !== "win32") await chmod(path, 0o700);
}

async function readCredentials(path: string, repository: string): Promise<StoredCredentials | null> {
  const metadata = await lstat(path).catch(() => null);
  if (!metadata) return null;
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error("GitHub credential file must be a regular file, not a symbolic link");
  if (metadata.size > credentialLimit) throw new Error("GitHub credential file is unexpectedly large");
  if (platform() !== "win32" && (metadata.mode & 0o077) !== 0) throw new Error("GitHub credential file permissions must be 0600");
  let value: unknown;
  try { value = JSON.parse(await readFile(path, "utf8")) as unknown; }
  catch { throw new Error("GitHub credential file does not contain valid JSON"); }
  return parseStored(value, repository);
}

async function writeCredentials(path: string, credentials: StoredCredentials): Promise<void> {
  const directory = dirname(path);
  await secureDirectory(directory);
  const existing = await lstat(path).catch(() => null);
  if (existing && (!existing.isFile() || existing.isSymbolicLink())) throw new Error("GitHub credential file must be a regular file, not a symbolic link");
  const temporary = `${path}.${randomBytes(12).toString("hex")}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(credentials, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temporary, path);
    if (platform() !== "win32") await chmod(path, 0o600);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

function appJwt(app: PendingApp | StoredCredentials, now: Date): string {
  const timestamp = Math.floor(now.getTime() / 1_000);
  const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");
  const unsigned = `${encode({ alg: "RS256", typ: "JWT" })}.${encode({ iat: timestamp - 60, exp: timestamp + 540, iss: String(app.app_id) })}`;
  return `${unsigned}.${sign("RSA-SHA256", Buffer.from(unsigned), app.private_key).toString("base64url")}`;
}

function githubHeaders(authorization?: string, body = false): Record<string, string> {
  return {
    accept: "application/vnd.github+json",
    "x-github-api-version": githubVersion,
    "user-agent": "RepoRook-Service",
    ...(authorization ? { authorization: `Bearer ${authorization}` } : {}),
    ...(body ? { "content-type": "application/json" } : {}),
  };
}

async function command(args: string[], cwd: string): Promise<string> {
  return await new Promise<string>((resolvePromise, reject) => {
    execFile("git", args, { cwd, encoding: "utf8", maxBuffer: 64 * 1_024 }, (error, stdout, stderr) => {
      if (!error) return resolvePromise(stdout.trim());
      reject(new Error((stderr || error.message).trim().slice(0, 1_000)));
    });
  });
}

export function parseGitHubRemote(remote: string): string {
  const value = remote.trim();
  let path = "";
  if (/^https?:\/\//i.test(value) || /^ssh:\/\//i.test(value)) {
    const url = new URL(value);
    if (url.hostname.toLowerCase() !== "github.com") throw new Error("Git remote is not hosted on github.com");
    path = url.pathname.replace(/^\//, "");
  } else {
    const match = /^git@github\.com:([^\s]+)$/i.exec(value);
    if (!match) throw new Error("Git remote is not a supported GitHub URL");
    path = match[1] as string;
  }
  return safeRepository(path.replace(/\.git$/i, ""));
}

export async function detectGitHubRepository(repositoryPath: string): Promise<string> {
  return parseGitHubRemote(await command(["remote", "get-url", "origin"], resolve(repositoryPath)));
}

export class GitHubAppIntegration implements RemediationPublisher {
  readonly repository: string;
  private readonly credentialPath: string;
  private readonly fetcher: FetchLike;
  private readonly apiBase: string;
  private readonly githubBase: string;
  private readonly now: () => Date;
  private readonly flows = new Map<string, PendingFlow>();
  private credentials: StoredCredentials | null;
  private cachedToken: CachedToken | null = null;

  private constructor(options: GitHubAppIntegrationOptions, credentials: StoredCredentials | null) {
    this.repository = safeRepository(options.repository);
    this.credentialPath = resolve(options.credentialPath ?? defaultCredentialPath(this.repository));
    this.fetcher = options.fetch ?? fetch;
    this.apiBase = (options.apiBase ?? "https://api.github.com").replace(/\/$/, "");
    this.githubBase = (options.githubBase ?? "https://github.com").replace(/\/$/, "");
    this.now = options.now ?? (() => new Date());
    this.credentials = credentials;
    for (const base of [this.apiBase, this.githubBase]) {
      const url = new URL(base);
      if (url.protocol !== "https:" && url.hostname !== "127.0.0.1" && url.hostname !== "localhost") throw new Error("GitHub endpoints must use HTTPS");
    }
  }

  static async open(options: GitHubAppIntegrationOptions): Promise<GitHubAppIntegration> {
    const repository = safeRepository(options.repository);
    const path = resolve(options.credentialPath ?? defaultCredentialPath(repository));
    return new GitHubAppIntegration(options, await readCredentials(path, repository));
  }

  status(): GitHubAppStatus {
    return { enabled: this.credentials !== null, connectable: true, repository: this.repository, mode: "guided-app", app: this.credentials?.app_slug ?? null };
  }

  beginManifest(originInput: string): GitHubManifestRequest {
    const origin = safeLoopbackOrigin(originInput);
    const state = randomBytes(32).toString("base64url");
    const suffix = randomBytes(4).toString("hex").slice(0, 6);
    const repositoryName = (this.repository.split("/")[1] as string).slice(0, 14);
    this.pruneFlows();
    this.flows.set(state, { expires_at: this.now().getTime() + flowLifetimeMs, origin, stage: "manifest" });
    const manifest = {
      name: `RepoRook ${repositoryName} ${suffix}`,
      url: "https://github.com/cisoventures/RepoRook",
      description: `Repository-only RepoRook draft fixes for ${this.repository}`,
      redirect_url: `${origin}/github/manifest/callback`,
      setup_url: `${origin}/github/install/callback?state=${encodeURIComponent(state)}`,
      public: false,
      default_events: [],
      default_permissions: installationPermissions,
      request_oauth_on_install: false,
      setup_on_update: false,
    };
    return {
      action: `${this.githubBase}/settings/apps/new?state=${encodeURIComponent(state)}`,
      manifest: JSON.stringify(manifest),
    };
  }

  async completeManifest(codeInput: string, state: string): Promise<string> {
    const code = codeInput.trim();
    if (!/^[A-Za-z0-9_-]{10,200}$/.test(code)) throw new Error("GitHub returned an invalid manifest code");
    const flow = this.flow(state, "manifest");
    const response = await this.fetcher(`${this.apiBase}/app-manifests/${encodeURIComponent(code)}/conversions`, {
      method: "POST",
      headers: githubHeaders(undefined, true),
      body: "{}",
    });
    const value = await response.json().catch(() => null) as unknown;
    if (!response.ok) {
      this.flows.delete(state);
      throw new Error(this.githubError(value, response.status));
    }
    const result = object(value, "GitHub App manifest");
    const appId = Number(result.id);
    const appSlug = requiredString(result.slug, "GitHub App slug");
    if (!Number.isSafeInteger(appId) || appId <= 0 || !/^[a-z0-9-]{1,100}$/.test(appSlug)) throw new Error("GitHub App manifest returned invalid identifiers");
    flow.stage = "installation";
    flow.app = { app_id: appId, app_slug: appSlug, private_key: validPrivateKey(result.pem) };
    return `${this.githubBase}/apps/${encodeURIComponent(appSlug)}/installations/new?state=${encodeURIComponent(state)}`;
  }

  async completeInstallation(installationIdInput: string, state: string): Promise<void> {
    if (!/^\d{1,20}$/.test(installationIdInput)) throw new Error("GitHub returned an invalid installation identifier");
    const installationId = Number(installationIdInput);
    if (!Number.isSafeInteger(installationId) || installationId <= 0) throw new Error("GitHub returned an invalid installation identifier");
    const flow = this.flow(state, "installation");
    if (!flow.app) throw new Error("GitHub App onboarding state is incomplete");
    const jwt = appJwt(flow.app, this.now());
    const repository = encodedRepository(this.repository);
    const response = await this.fetcher(`${this.apiBase}/repos/${repository}/installation`, { headers: githubHeaders(jwt) });
    const value = await response.json().catch(() => null) as unknown;
    if (!response.ok) throw new Error(`The GitHub App is not installed on ${this.repository}: ${this.githubError(value, response.status)}`);
    const returnedId = Number(object(value, "GitHub repository installation").id);
    if (returnedId !== installationId) throw new Error("GitHub installation callback did not match the selected repository");
    const credentials: StoredCredentials = {
      schema_version: "1.0",
      repository: this.repository,
      app_id: flow.app.app_id,
      app_slug: flow.app.app_slug,
      installation_id: installationId,
      private_key: flow.app.private_key,
      created_at: this.now().toISOString(),
    };
    await this.mintToken(credentials);
    await writeCredentials(this.credentialPath, credentials);
    this.credentials = credentials;
    this.flows.delete(state);
  }

  async disconnect(): Promise<void> {
    const metadata = await lstat(this.credentialPath).catch(() => null);
    if (metadata && (!metadata.isFile() || metadata.isSymbolicLink())) throw new Error("GitHub credential file must be a regular file, not a symbolic link");
    await rm(this.credentialPath, { force: true });
    this.credentials = null;
    this.cachedToken = null;
    this.flows.clear();
  }

  async publish(publication: RemediationPublication): Promise<PublishedPullRequest> {
    if (!this.credentials) throw new Error(`Connect the repository-only GitHub App to ${this.repository} before publishing`);
    return await new GitHubPublisher({
      repository: this.repository,
      tokenProvider: async () => await this.installationToken(),
      fetch: this.fetcher,
      apiBase: this.apiBase,
    }).publish(publication);
  }

  private pruneFlows(): void {
    const now = this.now().getTime();
    for (const [state, flow] of this.flows) if (flow.expires_at <= now) this.flows.delete(state);
  }

  private flow(state: string, stage: PendingFlow["stage"]): PendingFlow {
    this.pruneFlows();
    if (!/^[A-Za-z0-9_-]{40,100}$/.test(state)) throw new Error("GitHub onboarding state is missing or invalid");
    const flow = this.flows.get(state);
    if (!flow || flow.stage !== stage) throw new Error("GitHub onboarding state expired or was already used");
    return flow;
  }

  private githubError(value: unknown, status: number): string {
    if (value && typeof value === "object" && !Array.isArray(value) && typeof (value as Record<string, unknown>).message === "string") {
      return String((value as Record<string, unknown>).message).slice(0, 1_000);
    }
    return `GitHub API returned ${status}`;
  }

  private async installationToken(): Promise<string> {
    const now = this.now().getTime();
    if (this.cachedToken && this.cachedToken.expires_at - now > 2 * 60 * 1_000) return this.cachedToken.value;
    if (!this.credentials) throw new Error("GitHub App is not connected");
    return await this.mintToken(this.credentials);
  }

  private async mintToken(credentials: StoredCredentials): Promise<string> {
    const jwt = appJwt(credentials, this.now());
    const repositoryName = this.repository.split("/")[1];
    const response = await this.fetcher(`${this.apiBase}/app/installations/${credentials.installation_id}/access_tokens`, {
      method: "POST",
      headers: githubHeaders(jwt, true),
      body: JSON.stringify({ repositories: [repositoryName], permissions: installationPermissions }),
    });
    const value = await response.json().catch(() => null) as unknown;
    if (!response.ok) throw new Error(`GitHub could not create a repository-only installation token: ${this.githubError(value, response.status)}`);
    const result = object(value, "GitHub installation token");
    const token = requiredString(result.token, "GitHub installation token").trim();
    const expiresAt = Date.parse(requiredString(result.expires_at, "GitHub installation token expiry"));
    if (token.length < 20 || /\s/.test(token) || !Number.isFinite(expiresAt) || expiresAt <= this.now().getTime()) {
      throw new Error("GitHub returned an invalid installation token");
    }
    this.cachedToken = { value: token, expires_at: expiresAt };
    return token;
  }
}
