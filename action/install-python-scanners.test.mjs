import test from "node:test";
import assert from "node:assert/strict";
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execute = promisify(execFile);

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "reporook-python-installer-"));
  const action = join(root, "action");
  const bin = join(root, "bin");
  await Promise.all([mkdir(action), mkdir(bin)]);
  await copyFile(resolve("action/install-python-scanners.sh"), join(action, "install-python-scanners.sh"));
  const python = join(bin, "python3");
  await writeFile(python, '#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "$REPOROOK_TEST_PYTHON_ARGS"\n');
  await chmod(python, 0o755);
  return { root, action, bin };
}

test("missing Python hash lock performs no package installation and marks scanners unverified", async () => {
  const { root, action, bin } = await fixture();
  const args = join(root, "args.txt");
  const githubEnv = join(root, "github-env.txt");
  try {
    const result = await execute("bash", [join(action, "install-python-scanners.sh")], {
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, GITHUB_ENV: githubEnv, REPOROOK_TEST_PYTHON_ARGS: args },
    });
    assert.match(result.stderr, /has no repository-owned hash lock/);
    await assert.rejects(readFile(args, "utf8"), /ENOENT/);
    assert.equal(await readFile(githubEnv, "utf8"), "REPOROOK_PYTHON_SCANNERS_VERIFIED=false\n");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a repository-owned lock is passed to pip in strict hash and wheel-only mode", async () => {
  const { root, action, bin } = await fixture();
  const args = join(root, "args.txt");
  const githubEnv = join(root, "github-env.txt");
  const lock = join(action, "python-scanners.requirements.txt");
  try {
    await writeFile(lock, [
      `semgrep==1.171.0 --hash=sha256:${"a".repeat(64)}`,
      `pip-audit==2.10.1 --hash=sha256:${"b".repeat(64)}`,
      `checkov==3.3.8 --hash=sha256:${"c".repeat(64)}`,
      "",
    ].join("\n"));
    await execute("bash", [join(action, "install-python-scanners.sh")], {
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, GITHUB_ENV: githubEnv, REPOROOK_TEST_PYTHON_ARGS: args },
    });
    const invocation = await readFile(args, "utf8");
    assert.match(invocation, /^-m\npip\ninstall\n/m);
    assert.match(invocation, /--force-reinstall/);
    assert.match(invocation, /--only-binary=:all:/);
    assert.match(invocation, /--require-hashes/);
    assert.match(invocation, new RegExp(lock.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.equal(await readFile(githubEnv, "utf8"), "REPOROOK_PYTHON_SCANNERS_VERIFIED=false\nREPOROOK_PYTHON_SCANNERS_VERIFIED=true\n");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a symbolic-link Python lock is rejected before pip", { skip: process.platform === "win32" }, async () => {
  const { root, action, bin } = await fixture();
  const args = join(root, "args.txt");
  const githubEnv = join(root, "github-env.txt");
  const outside = join(root, "outside.txt");
  try {
    await writeFile(outside, `semgrep==1.171.0 --hash=sha256:${"a".repeat(64)}\n`);
    await symlink(outside, join(action, "python-scanners.requirements.txt"));
    await assert.rejects(
      execute("bash", [join(action, "install-python-scanners.sh")], {
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, GITHUB_ENV: githubEnv, REPOROOK_TEST_PYTHON_ARGS: args },
      }),
      (error) => error.code === 2 && /symbolic-link/.test(error.stderr),
    );
    await assert.rejects(readFile(args, "utf8"), /ENOENT/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a hash lock missing any required scanner pin is rejected before pip", async () => {
  const { root, action, bin } = await fixture();
  const args = join(root, "args.txt");
  const githubEnv = join(root, "github-env.txt");
  try {
    await writeFile(join(action, "python-scanners.requirements.txt"), [
      `# semgrep==1.171.0 --hash=sha256:${"a".repeat(64)}`,
      `pip-audit==2.10.1 --hash=sha256:${"b".repeat(64)}`,
      `checkov==3.3.8 --hash=sha256:${"c".repeat(64)}`,
      "",
    ].join("\n"));
    await assert.rejects(
      execute("bash", [join(action, "install-python-scanners.sh")], {
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, GITHUB_ENV: githubEnv, REPOROOK_TEST_PYTHON_ARGS: args },
      }),
      (error) => error.code === 2 && /missing required pin semgrep==1\.171\.0/.test(error.stderr),
    );
    await assert.rejects(readFile(args, "utf8"), /ENOENT/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
