import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GitHubAppIntegration, parseGitHubRemote } from "../dist/github-app.js";

const repository = "cisoventures/RepoRook";
const privateKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" });

function response(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

function githubMock(options = {}) {
  const calls = [];
  const fetch = async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method ?? "GET";
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ method, path: `${url.pathname}${url.search}`, headers: init.headers, body });
    if (url.pathname.startsWith("/app-manifests/")) {
      return response({ id: 12345, slug: "reporook-reporook-test", pem: privateKey, webhook_secret: "discard-me", client_secret: "discard-me-too" }, 201);
    }
    if (url.pathname === "/repos/cisoventures/RepoRook/installation") {
      return response({ id: options.repositoryInstallationId ?? 67890, repository_selection: "selected" });
    }
    if (url.pathname === "/app/installations/67890/access_tokens") {
      return response({ token: "ghs_12345_valid_stateless_installation_token", expires_at: "2026-07-26T19:00:00.000Z" }, 201);
    }
    return response({ message: `Unexpected request: ${method} ${url.pathname}` }, 500);
  };
  return { calls, fetch };
}

test("GitHub remote parsing accepts common github.com forms and rejects other hosts", () => {
  assert.equal(parseGitHubRemote("https://github.com/cisoventures/RepoRook.git"), repository);
  assert.equal(parseGitHubRemote("git@github.com:cisoventures/RepoRook.git"), repository);
  assert.equal(parseGitHubRemote("ssh://git@github.com/cisoventures/RepoRook.git"), repository);
  assert.throws(() => parseGitHubRemote("https://example.com/cisoventures/RepoRook.git"), /not hosted on github\.com/);
  assert.throws(() => parseGitHubRemote("file:///tmp/repository"), /not a supported GitHub URL/);
});

test("guided App onboarding requests and persists only one repository boundary", async () => {
  const directory = await mkdtemp(join(tmpdir(), "reporook-github-app-test-"));
  const credentialPath = join(directory, "credentials", "github.json");
  const mock = githubMock();
  const now = () => new Date("2026-07-26T18:00:00.000Z");
  try {
    const integration = await GitHubAppIntegration.open({ repository, credentialPath, fetch: mock.fetch, now });
    assert.equal(integration.status().enabled, false);
    const request = integration.beginManifest("http://127.0.0.1:7377");
    const action = new URL(request.action);
    const state = action.searchParams.get("state");
    assert.match(state, /^[A-Za-z0-9_-]{40,100}$/);
    const manifest = JSON.parse(request.manifest);
    assert.equal(manifest.public, false);
    assert.equal(manifest.request_oauth_on_install, false);
    assert.equal(manifest.setup_on_update, false);
    assert.deepEqual(manifest.default_events, []);
    assert.deepEqual(manifest.default_permissions, { metadata: "read", contents: "write", pull_requests: "write" });
    assert.equal("hook_attributes" in manifest, false);
    assert.match(manifest.setup_url, new RegExp(`state=${state}$`));

    const installationUrl = await integration.completeManifest("manifest_code_12345", state);
    assert.equal(new URL(installationUrl).pathname, "/apps/reporook-reporook-test/installations/new");
    await assert.rejects(integration.completeManifest("manifest_code_12345", state), /expired or was already used/);
    await integration.completeInstallation("67890", state);
    assert.equal(integration.status().enabled, true);
    assert.equal(integration.status().repository, repository);

    const tokenCall = mock.calls.find((call) => call.path === "/app/installations/67890/access_tokens");
    assert.deepEqual(tokenCall.body, { repositories: ["RepoRook"], permissions: { metadata: "read", contents: "write", pull_requests: "write" } });
    assert.match(tokenCall.headers.authorization, /^Bearer [^.]+\.[^.]+\.[^.]+$/);
    const stored = await readFile(credentialPath, "utf8");
    assert.match(stored, /BEGIN PRIVATE KEY/);
    assert.doesNotMatch(stored, /ghs_12345/);
    assert.doesNotMatch(stored, /discard-me/);
    if (process.platform !== "win32") assert.equal((await lstat(credentialPath)).mode & 0o777, 0o600);

    const reopened = await GitHubAppIntegration.open({ repository, credentialPath, fetch: mock.fetch, now });
    assert.equal(reopened.status().enabled, true);
    assert.equal(reopened.status().app, "reporook-reporook-test");
    await reopened.disconnect();
    assert.equal(reopened.status().enabled, false);
    await assert.rejects(readFile(credentialPath), /ENOENT/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("spoofed installation callback cannot persist credentials or mint a token", async () => {
  const directory = await mkdtemp(join(tmpdir(), "reporook-github-app-spoof-test-"));
  const credentialPath = join(directory, "credentials", "github.json");
  const mock = githubMock({ repositoryInstallationId: 67890 });
  try {
    const integration = await GitHubAppIntegration.open({ repository, credentialPath, fetch: mock.fetch, now: () => new Date("2026-07-26T18:00:00.000Z") });
    const request = integration.beginManifest("http://127.0.0.1:7377");
    const state = new URL(request.action).searchParams.get("state");
    await integration.completeManifest("manifest_code_12345", state);
    await assert.rejects(integration.completeInstallation("99999", state), /did not match the selected repository/);
    assert.equal(integration.status().enabled, false);
    assert.equal(mock.calls.some((call) => call.path.includes("/access_tokens")), false);
    await assert.rejects(readFile(credentialPath), /ENOENT/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
