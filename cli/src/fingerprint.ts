import { createHash } from "node:crypto";

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function findingFingerprint(parts: Array<string | number | null | undefined>): {
  id: string;
  fingerprint: string;
} {
  const canonical = parts
    .map((part) => String(part ?? "").trim().replace(/\s+/g, " "))
    .join("\u241f");
  const digest = sha256(canonical);
  return { id: `rr-${digest.slice(0, 12)}`, fingerprint: `sha256:${digest}` };
}
