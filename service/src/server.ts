import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { URL } from "node:url";
import { RepositoryStore } from "./repository.js";
import { runRepoRook, type CliRunner } from "./runner.js";
import { dashboardCss, dashboardHtml, dashboardJs } from "./ui.js";

const maxBodyBytes = 64 * 1024;
const sessionCookie = "reporook_session";

export interface DashboardServerOptions {
  repository: string;
  host?: "127.0.0.1" | "::1";
  port?: number;
  cliRunner?: CliRunner;
  bootstrapToken?: string;
  sessionToken?: string;
}

export interface ScanJob {
  status: "idle" | "running" | "completed" | "failed";
  started_at: string | null;
  finished_at: string | null;
  exit_code: number | null;
  message: string;
}

export interface RunningDashboard {
  server: Server;
  origin: string;
  bootstrap_url: string;
  close: () => Promise<void>;
}

function json(response: ServerResponse, code: number, value: unknown): void {
  securityHeaders(response);
  response.statusCode = code;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("cache-control", "no-store");
  response.end(`${JSON.stringify(value)}\n`);
}

function text(response: ServerResponse, code: number, type: string, value: string): void {
  securityHeaders(response);
  response.statusCode = code;
  response.setHeader("content-type", `${type}; charset=utf-8`);
  response.setHeader("cache-control", "no-store");
  response.end(value);
}

function securityHeaders(response: ServerResponse): void {
  response.setHeader("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("x-frame-options", "DENY");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  response.setHeader("cross-origin-resource-policy", "same-origin");
}

async function body(request: IncomingMessage): Promise<Record<string, unknown>> {
  const contentType = request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") throw new HttpError(415, "Requests must use application/json");
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const value of request) {
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    size += chunk.byteLength;
    if (size > maxBodyBytes) throw new HttpError(413, "Request body exceeds 64 KiB");
    chunks.push(chunk);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); }
  catch { throw new HttpError(400, "Request body must contain valid JSON"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new HttpError(400, "Request body must be a JSON object");
  return parsed as Record<string, unknown>;
}

function cookies(request: IncomingMessage): Map<string, string> {
  const output = new Map<string, string>();
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0) output.set(part.slice(0, index).trim(), part.slice(index + 1).trim());
  }
  return output;
}

function equalSecret(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.byteLength === b.byteLength && timingSafeEqual(a, b);
}

function stringValue(input: unknown, label: string, minimum: number, maximum: number): string {
  if (typeof input !== "string") throw new HttpError(400, `${label} is required`);
  const value = input.trim();
  if (value.length < minimum || value.length > maximum) throw new HttpError(400, `${label} must be ${minimum}-${maximum} characters`);
  return value;
}

class HttpError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}

export async function startDashboardServer(options: DashboardServerOptions): Promise<RunningDashboard> {
  const host = options.host ?? "127.0.0.1";
  if (!(["127.0.0.1", "::1"] as const).includes(host)) throw new Error("RepoRook service only binds to a loopback address");
  if (isIP(host) === 0) throw new Error("RepoRook service host must be a literal loopback IP address");
  const port = options.port ?? 7377;
  if (!Number.isInteger(port) || port < 0 || port > 65_535) throw new Error("Service port must be between 0 and 65535");
  const store = await RepositoryStore.open(options.repository);
  const cli = options.cliRunner ?? runRepoRook;
  const bootstrapToken = options.bootstrapToken ?? randomBytes(32).toString("base64url");
  const sessionToken = options.sessionToken ?? randomBytes(32).toString("base64url");
  let origin = "";
  let job: ScanJob = { status: "idle", started_at: null, finished_at: null, exit_code: null, message: "Ready" };

  const server = createServer(async (request, response) => {
    try {
      if (!origin) throw new HttpError(503, "Service is starting");
      const expectedHost = new URL(origin).host;
      if (request.headers.host !== expectedHost) throw new HttpError(421, "Unexpected Host header");
      const url = new URL(request.url ?? "/", origin);
      const method = request.method ?? "GET";
      const hasSession = equalSecret(cookies(request).get(sessionCookie) ?? "", sessionToken);
      const isMutation = method !== "GET" && method !== "HEAD";
      if (isMutation && url.pathname !== "/api/session" && request.headers.origin !== origin) throw new HttpError(403, "Origin check failed");

      if (method === "GET" && url.pathname === "/") return text(response, 200, "text/html", dashboardHtml());
      if (method === "GET" && url.pathname === "/assets/app.css") return text(response, 200, "text/css", dashboardCss);
      if (method === "GET" && url.pathname === "/assets/app.js") return text(response, 200, "text/javascript", dashboardJs);
      if (method === "POST" && url.pathname === "/api/session") {
        if (request.headers.origin !== origin) throw new HttpError(403, "Origin check failed");
        const input = await body(request);
        if (typeof input.token !== "string" || !equalSecret(input.token, bootstrapToken)) throw new HttpError(401, "Invalid dashboard token");
        response.setHeader("set-cookie", `${sessionCookie}=${sessionToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`);
        return json(response, 200, { authenticated: true });
      }
      if (!hasSession) throw new HttpError(401, "Dashboard session required");
      if (method === "GET" && url.pathname === "/api/status") return json(response, 200, await store.snapshot());
      if (method === "GET" && url.pathname === "/api/job") return json(response, 200, job);
      if (method === "POST" && url.pathname === "/api/onboard") {
        const input = await body(request);
        if (input.confirmation !== "initialize RepoRook") throw new HttpError(400, "Onboarding confirmation did not match");
        const result = await cli(["init", store.target, "--format", "json"]);
        if (result.code !== 0) throw new HttpError(422, result.stderr.trim() || "RepoRook initialization failed");
        return json(response, 200, JSON.parse(result.stdout) as unknown);
      }
      if (method === "POST" && url.pathname === "/api/scan") {
        await body(request);
        if (job.status === "running") throw new HttpError(409, "A scan is already running");
        job = { status: "running", started_at: new Date().toISOString(), finished_at: null, exit_code: null, message: "Scanner evidence is being collected" };
        void cli(["scan", store.target, "--require-scanners", "--quiet"]).then((result) => {
          const completed = result.code === 0 || result.code === 1;
          job = {
            status: completed ? "completed" : "failed",
            started_at: job.started_at,
            finished_at: new Date().toISOString(),
            exit_code: result.code,
            message: completed ? (result.code === 1 ? "Scan completed with actionable findings" : "Scan completed") : (result.stderr.trim().slice(0, 1_000) || "Scan coverage failed"),
          };
        }).catch((error: Error) => {
          job = { status: "failed", started_at: job.started_at, finished_at: new Date().toISOString(), exit_code: 2, message: error.message.slice(0, 1_000) };
        });
        return json(response, 202, job);
      }
      if (method === "POST" && url.pathname === "/api/plan") {
        const input = await body(request);
        const findingId = stringValue(input.finding_id, "finding_id", 15, 15);
        if (!/^rr-[a-f0-9]{12}$/.test(findingId)) throw new HttpError(400, "Invalid finding ID");
        const result = await cli(["plan", findingId, store.target, "--format", "json"]);
        if (result.code !== 0) throw new HttpError(422, result.stderr.trim() || "RepoRook could not prepare the plan");
        return json(response, 200, JSON.parse(result.stdout) as unknown);
      }
      if (method === "POST" && url.pathname === "/api/approve") {
        const input = await body(request);
        const findingId = stringValue(input.finding_id, "finding_id", 15, 15);
        if (!/^rr-[a-f0-9]{12}$/.test(findingId)) throw new HttpError(400, "Invalid finding ID");
        const digest = stringValue(input.proposal_digest, "proposal_digest", 64, 64);
        if (!/^[a-f0-9]{64}$/.test(digest)) throw new HttpError(400, "Invalid proposal digest");
        const currentDigest = await store.proposalDigest(findingId);
        if (!equalSecret(digest, currentDigest)) throw new HttpError(409, "The proposal changed after it was displayed; review the new exact patch before approving");
        const approvedBy = stringValue(input.approved_by, "approved_by", 2, 100);
        const reason = stringValue(input.reason, "reason", 10, 500);
        const result = await cli(["approve", findingId, store.target, "--approved-by", approvedBy, "--reason", reason, "--format", "json"]);
        if (result.code !== 0) throw new HttpError(422, result.stderr.trim() || "RepoRook could not record the approval");
        return json(response, 200, JSON.parse(result.stdout) as unknown);
      }
      throw new HttpError(404, "Not found");
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      const message = error instanceof Error ? error.message : "Unexpected service error";
      json(response, status, { error: message });
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => { server.off("error", reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("RepoRook service did not receive a TCP address");
  const displayHost = address.family === "IPv6" ? `[${address.address}]` : address.address;
  origin = `http://${displayHost}:${address.port}`;
  return {
    server,
    origin,
    bootstrap_url: `${origin}/#token=${encodeURIComponent(bootstrapToken)}`,
    close: async () => await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}
