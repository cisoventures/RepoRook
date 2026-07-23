import { copyFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const fixture = fileURLToPath(new URL("../test-fixtures/vulnerable-app/", import.meta.url));
const sources = join(fixture, "fixture-manifests");
const manifests = [
  ["npm-package.fixture", "package.json"],
  ["npm-lock.fixture", "package-lock.json"],
  ["python-requirements.fixture", "requirements.txt"],
];

for (const [source, destination] of manifests) {
  await copyFile(join(sources, source), join(fixture, destination));
}

process.stdout.write(`Materialized ${manifests.length} intentionally vulnerable manifests for local testing.\n`);
