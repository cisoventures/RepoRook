import test from "node:test";
import assert from "node:assert/strict";
import { parseArgs } from "../dist/args.js";

test("argument parsing supports an end-of-options delimiter", () => {
  const parsed = parseArgs(["scan", "--format", "json", "--", "--output"]);
  assert.equal(parsed.command, "scan");
  assert.deepEqual(parsed.flags, { format: "json" });
  assert.deepEqual(parsed.positionals, ["--output"]);
});
