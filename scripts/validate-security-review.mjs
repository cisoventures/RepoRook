import { execFileSync } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const contract = await readJson("contracts/security-review.json");
const manifest = await readJson("package.json");
let checks = 0;

function assert(condition, message) {
  checks += 1;
  if (!condition) throw new Error(message);
}

function assertEqual(label, actual, expected) {
  assert(isDeepStrictEqual(actual, expected), `${label} drifted:\nexpected ${JSON.stringify(expected, null, 2)}\nactual   ${JSON.stringify(actual, null, 2)}`);
}

function repositoryPath(path) {
  const target = resolve(root, path);
  const traversal = relative(root, target);
  if (traversal === ".." || traversal.startsWith(`..${sep}`)) throw new Error(`Security-review path escapes the repository: ${path}`);
  return target;
}

async function readJson(path) {
  return JSON.parse(await readFile(repositoryPath(path), "utf8"));
}

assertEqual("security-review status", contract.status, "stable");
assertEqual("independent-review claim", contract.claims.independent_review_completed, false);
assertEqual("security-opinion claim", contract.claims.security_opinion_provided, false);
assertEqual("network claim", contract.claims.network_access_required, false);
assertEqual("network sandbox claim", contract.claims.network_sandbox_enforced, false);
assertEqual("external installation claim", contract.claims.external_software_installation_performed, false);
assertEqual("scanner installation claim", contract.claims.scanner_installation_performed, false);
assertEqual("local RepoRook installation disclosure", contract.claims.temporary_local_reporook_installation, true);
assertEqual("review output", contract.output, "outputs/security-review-baseline.json");
assertEqual("unique command identifiers", [...new Set(contract.commands.map((command) => command.id))], contract.commands.map((command) => command.id));
assertEqual("unique integrity paths", [...new Set(contract.integrity_paths)], contract.integrity_paths);
assertEqual("unique review scope", [...new Set(contract.review_scope)], contract.review_scope);
assertEqual("unique starting evidence", [...new Set(contract.starting_evidence)], contract.starting_evidence);

for (const path of [...contract.integrity_paths, ...contract.review_scope, ...contract.starting_evidence]) {
  const metadata = await lstat(repositoryPath(path));
  assert(!metadata.isSymbolicLink(), `Security-review scope cannot be a symbolic link: ${path}`);
  assert(metadata.isFile() || metadata.isDirectory(), `Security-review scope is not a regular file or directory: ${path}`);
}

const forbidden = /(?:^|\s)(?:install|ci|exec|dlx|npx|bunx|curl|wget|pip)(?:\s|$)/i;
for (const command of contract.commands) {
  assertEqual(`${command.id} executable`, command.command, "npm");
  assertEqual(`${command.id} npm verb`, command.args[0], "run");
  const script = command.args[1];
  assert(typeof manifest.scripts?.[script] === "string", `${command.id} references missing npm script ${script}`);
  assert(!forbidden.test([command.command, ...command.args].join(" ")), `${command.id} may install or bootstrap software`);
  assert(typeof command.purpose === "string" && command.purpose.length >= 20, `${command.id} lacks a reviewable purpose`);
}

for (const [name, expected] of Object.entries({
  npm_config_offline: "true",
  npm_config_ignore_scripts: "true",
  npm_config_audit: "false",
  npm_config_fund: "false",
})) assertEqual(`baseline environment ${name}`, contract.environment[name], expected);

const plan = JSON.parse(execFileSync(process.execPath, [repositoryPath("scripts/run-security-review-baseline.mjs"), "--plan"], { encoding: "utf8" }));
assertEqual("runner claims", plan.claims, contract.claims);
assertEqual("runner output", plan.output, contract.output);
assertEqual(
  "runner commands",
  plan.commands.map(({ id, command, args, purpose }) => ({ id, command, args, purpose })),
  contract.commands.map(({ id, command, args, purpose }) => ({ id, command, args, purpose })),
);

const review = await readFile(repositoryPath("docs/SECURITY_REVIEW.md"), "utf8");
assert(review.includes("npm run review:baseline"), "External review guide does not document the baseline command");
assert(review.includes(contract.output), "External review guide does not document the evidence output");
assert(/not an independent review or a security opinion/i.test(review), "External review guide could misstate baseline evidence as an audit opinion");
for (const field of contract.required_report_fields) assert(review.includes(`\`${field}\``), `External review guide does not document report field ${field}`);
const manualMethodMarkers = {
  "filesystem-process-credential-approval-boundary-review": "Manual source review of every filesystem, process, credential, and approval boundary.",
  "coverage-guided-fuzzing": "Property or coverage-guided fuzzing beyond the committed seeded corpus",
  "cross-platform-hostile-filesystem-testing": "Linux, macOS, and Windows hostile-filesystem tests",
  "fault-injection": "Fault injection for truncated files",
  "package-and-workflow-permission-review": "Package-tarball and workflow permission review from a clean clone.",
  "secret-retention-validation": "cannot retain secret-shaped scanner fields.",
};
assertEqual("manual review method identifiers", contract.required_manual_methods, Object.keys(manualMethodMarkers));
for (const [method, marker] of Object.entries(manualMethodMarkers)) {
  assert(review.includes(marker), `External review guide lost required manual method ${method}`);
}

assertEqual("root baseline script", manifest.scripts?.["review:baseline"], "node scripts/run-security-review-baseline.mjs");
assertEqual("root review validator", manifest.scripts?.["validate:review-package"], "node scripts/validate-security-review.mjs");
assert(manifest.scripts?.check?.includes("validate:review-package"), "npm run check does not enforce the external-review package contract");

process.stdout.write(`RepoRook external-review package passed ${checks} checks.\n`);
