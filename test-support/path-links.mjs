import { symlink, unlink } from "node:fs/promises";
import { resolve } from "node:path";

export async function createDirectoryLink(target, path) {
  await symlink(resolve(target), path, process.platform === "win32" ? "junction" : "dir");
}

export async function removeDirectoryLink(path) {
  await unlink(path).catch((error) => {
    if (error?.code !== "ENOENT") throw error;
  });
}
