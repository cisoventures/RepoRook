import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";

export const maximumEvidenceBytes = 10 * 1024 * 1024;
export const maximumScannerReportBytes = 50 * 1024 * 1024;

function limitLabel(maximumBytes: number): string {
  if (maximumBytes % (1024 * 1024) === 0) return `${maximumBytes / (1024 * 1024)} MiB`;
  if (maximumBytes % 1024 === 0) return `${maximumBytes / 1024} KiB`;
  return `${maximumBytes} bytes`;
}

export async function readBoundedTextFile(path: string, label: string, maximumBytes = maximumEvidenceBytes): Promise<string> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) throw new Error("Input byte limit must be a positive safe integer");
  const before = await lstat(path);
  if (before.isSymbolicLink()) throw new Error(`${label} must not be a symbolic link`);
  if (!before.isFile()) throw new Error(`${label} must be a regular file`);
  if (before.size > maximumBytes) throw new Error(`${label} exceeds the ${limitLabel(maximumBytes)} limit`);

  const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
  const handle = await open(path, constants.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat();
    if (!opened.isFile()) throw new Error(`${label} must be a regular file`);
    if (opened.size > maximumBytes) throw new Error(`${label} exceeds the ${limitLabel(maximumBytes)} limit`);
    const chunks: Buffer[] = [];
    let total = 0;
    while (total <= maximumBytes) {
      const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes + 1 - total));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      chunks.push(buffer.subarray(0, bytesRead));
      total += bytesRead;
    }
    if (total > maximumBytes) throw new Error(`${label} exceeds the ${limitLabel(maximumBytes)} limit`);
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
    } catch {
      throw new Error(`${label} must contain valid UTF-8 text`);
    }
  } finally {
    await handle.close();
  }
}

export async function readBoundedJsonFile(path: string, label: string, maximumBytes = maximumEvidenceBytes): Promise<unknown> {
  const text = await readBoundedTextFile(path, label, maximumBytes);
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${(error as Error).message}`);
  }
}
