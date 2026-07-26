import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const temporary = await mkdtemp(join(tmpdir(), "reporook-packages-"));
const supplied = process.argv[2];
const distributions = supplied ? resolve(supplied) : join(temporary, "distributions");

try {
  if (!supplied) {
    await mkdir(distributions, { recursive: true });
    execFileSync(npm, ["pack", "--workspace", "reporook", "--pack-destination", distributions], { stdio: "inherit" });
    execFileSync(npm, ["pack", "--workspace", "@reporook/mcp-server", "--pack-destination", distributions], { stdio: "inherit" });
    execFileSync(npm, ["pack", "--workspace", "@reporook/service", "--pack-destination", distributions], { stdio: "inherit" });
  }
  const cliPackage = JSON.parse(await readFile("cli/package.json", "utf8"));
  const mcpPackage = JSON.parse(await readFile("mcp-server/package.json", "utf8"));
  const servicePackage = JSON.parse(await readFile("service/package.json", "utf8"));
  const cliTarball = join(distributions, `reporook-${cliPackage.version}.tgz`);
  const mcpTarball = join(distributions, `reporook-mcp-server-${mcpPackage.version}.tgz`);
  const serviceTarball = join(distributions, `reporook-service-${servicePackage.version}.tgz`);
  const installation = join(temporary, "installation");
  await mkdir(installation, { recursive: true });
  execFileSync(npm, ["init", "--yes"], { cwd: installation, stdio: "ignore" });
  execFileSync(npm, ["install", "--offline", "--ignore-scripts", "--package-lock=false", cliTarball], { cwd: installation, stdio: "inherit" });
  execFileSync(npm, ["install", "--offline", "--ignore-scripts", "--package-lock=false", mcpTarball], { cwd: installation, stdio: "inherit" });
  execFileSync(npm, ["install", "--offline", "--ignore-scripts", "--package-lock=false", serviceTarball], { cwd: installation, stdio: "inherit" });

  const cliEntry = join(installation, "node_modules", "reporook", "dist", "index.js");
  const version = execFileSync(process.execPath, [cliEntry, "--version"], { encoding: "utf8" }).trim();
  if (version !== cliPackage.version) throw new Error(`Packed CLI returned ${version}, expected ${cliPackage.version}`);
  const help = execFileSync(process.execPath, [cliEntry, "--help"], { encoding: "utf8" });
  if (!/reporook init/.test(help) || !/reporook plan/.test(help) || !/reporook integrate/.test(help)) throw new Error("Packed CLI did not expose the guided-fix and integration commands");
  const packagedAdapter = join(installation, "node_modules", "reporook", "dist", "integrations", "codex", "reporook", ".codex-plugin", "plugin.json");
  if (!(await stat(packagedAdapter)).isFile()) throw new Error("Packed CLI did not include native agent integration assets");
  const sample = join(temporary, "sample");
  await mkdir(join(sample, "src"), { recursive: true });
  await writeFile(join(sample, "src", "app.js"), "export const ready = true;\n");
  const initialized = JSON.parse(execFileSync(process.execPath, [cliEntry, "init", sample, "--format", "json"], { encoding: "utf8" }));
  if (initialized.status !== "created" || !initialized.profile?.recommended_scanners?.includes("semgrep")) {
    throw new Error("Packed CLI did not initialize and detect the sample project");
  }

  const mcpEntry = join(installation, "node_modules", "@reporook", "mcp-server", "dist", "index.js");
  const input = [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "package-smoke", version: "1" } } },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  ].map((message) => JSON.stringify(message)).join("\n") + "\n";
  const output = execFileSync(process.execPath, [mcpEntry], { input, encoding: "utf8" }).trim().split(/\r?\n/).map((line) => JSON.parse(line));
  const tools = output.find((message) => message.id === 2)?.result?.tools;
  const toolNames = new Set(Array.isArray(tools) ? tools.map((tool) => tool.name) : []);
  if (!["prioritize_findings", "prepare_remediation_plan", "verify_fix"].every((name) => toolNames.has(name))) {
    throw new Error("Packed MCP server did not expose the guided-fix and verification tools");
  }
  const serviceEntry = join(installation, "node_modules", "@reporook", "service", "dist", "index.js");
  const serviceVersion = execFileSync(process.execPath, [serviceEntry, "--version"], { encoding: "utf8" }).trim();
  if (serviceVersion !== servicePackage.version) throw new Error(`Packed service returned ${serviceVersion}, expected ${servicePackage.version}`);
  const serviceHelp = execFileSync(process.execPath, [serviceEntry, "--help"], { encoding: "utf8" });
  if (!/loopback/i.test(serviceHelp) || !/never\s+modifies local application code/i.test(serviceHelp) || !/installation token/i.test(serviceHelp)) throw new Error("Packed service did not disclose its security boundary");
  process.stdout.write(`Packed RepoRook ${version}, MCP server, and no-code service passed clean-install smoke tests.\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
