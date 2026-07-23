import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
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
  }
  const cliPackage = JSON.parse(await readFile("cli/package.json", "utf8"));
  const mcpPackage = JSON.parse(await readFile("mcp-server/package.json", "utf8"));
  const cliTarball = join(distributions, `reporook-${cliPackage.version}.tgz`);
  const mcpTarball = join(distributions, `reporook-mcp-server-${mcpPackage.version}.tgz`);
  const installation = join(temporary, "installation");
  await mkdir(installation, { recursive: true });
  execFileSync(npm, ["init", "--yes"], { cwd: installation, stdio: "ignore" });
  execFileSync(npm, ["install", "--offline", "--ignore-scripts", "--package-lock=false", cliTarball], { cwd: installation, stdio: "inherit" });
  execFileSync(npm, ["install", "--offline", "--ignore-scripts", "--package-lock=false", mcpTarball], { cwd: installation, stdio: "inherit" });

  const cliEntry = join(installation, "node_modules", "reporook", "dist", "index.js");
  const version = execFileSync(process.execPath, [cliEntry, "--version"], { encoding: "utf8" }).trim();
  if (version !== cliPackage.version) throw new Error(`Packed CLI returned ${version}, expected ${cliPackage.version}`);

  const mcpEntry = join(installation, "node_modules", "@reporook", "mcp-server", "dist", "index.js");
  const input = [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "package-smoke", version: "1" } } },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  ].map((message) => JSON.stringify(message)).join("\n") + "\n";
  const output = execFileSync(process.execPath, [mcpEntry], { input, encoding: "utf8" }).trim().split(/\r?\n/).map((line) => JSON.parse(line));
  const tools = output.find((message) => message.id === 2)?.result?.tools;
  if (!Array.isArray(tools) || !tools.some((tool) => tool.name === "verify_fix")) throw new Error("Packed MCP server did not expose verify_fix");
  process.stdout.write(`Packed RepoRook ${version} and MCP server passed clean-install smoke tests.\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
