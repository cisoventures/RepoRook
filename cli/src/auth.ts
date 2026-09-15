import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

export interface ArtifactAuthentication {
  scheme: "hmac-sha256";
  key_id: string;
  digest: string;
}

// This identifies the artifact-authentication scheme, not the secret key. A
// secret-derived identifier would give attackers a reusable offline verifier
// for weak automation secrets; the HMAC digest below is the authenticity proof.
const artifactAuthenticationKeyId = `sha256:${createHash("sha256").update("reporook-artifact-authentication:v1").digest("hex")}`;

function authenticationKey(): Buffer {
  const configured = process.env.REPOROOK_AUTH_KEY;
  if (configured !== undefined) {
    if (Buffer.byteLength(configured, "utf8") < 32 || /[\r\n\0]/.test(configured)) {
      throw new Error("REPOROOK_AUTH_KEY must contain at least 32 bytes and no control characters");
    }
    return Buffer.from(configured, "utf8");
  }
  const base = resolve(process.env.XDG_CACHE_HOME || join(homedir(), ".cache"));
  const directory = join(base, "reporook");
  const path = join(directory, "artifact-auth-key");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const directoryMetadata = lstatSync(directory);
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) throw new Error("RepoRook artifact authentication directory is invalid");
  // Windows does not expose its ACLs through POSIX mode bits. The cache lives
  // below the user's profile there, while creation and link/type checks below
  // still prevent replacing the key with attacker-selected filesystem objects.
  if (process.platform !== "win32") chmodSync(directory, 0o700);
  if (!existsSync(path)) {
    try { writeFileSync(path, randomBytes(32), { mode: 0o600, flag: "wx" }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
  }
  const metadata = lstatSync(path);
  const unsafePosixPermissions = process.platform !== "win32" && (metadata.mode & 0o077) !== 0;
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size !== 32 || unsafePosixPermissions) {
    throw new Error("RepoRook artifact authentication key is invalid or has unsafe permissions");
  }
  const key = readFileSync(path);
  if (key.byteLength !== 32) throw new Error("RepoRook artifact authentication key is invalid");
  return key;
}

function unsigned(value: Record<string, unknown>): Record<string, unknown> {
  const { authentication: _authentication, ...rest } = value;
  return rest;
}

function targetIdentity(target: string): string {
  const absolute = resolve(target);
  let canonical: string;
  try { canonical = realpathSync.native(absolute); }
  catch { canonical = absolute; }
  if (process.platform !== "win32") return canonical;
  // Windows APIs can return the same path with different drive-letter casing,
  // separators, or an extended-length prefix. Normalize those aliases so an
  // artifact signed by one process verifies in another without weakening the
  // repository-path binding.
  return canonical
    .replace(/^\\\\\?\\UNC\\/i, "//")
    .replace(/^\\\\\?\\/, "")
    .replaceAll("\\", "/")
    .toLowerCase();
}

export function artifactTargetsMatch(left: string, right: string): boolean {
  return targetIdentity(left) === targetIdentity(right);
}

function digestFor(key: Buffer, target: string, value: Record<string, unknown>): string {
  return `sha256:${createHmac("sha256", key).update(targetIdentity(target)).update("\0").update(JSON.stringify(unsigned(value))).digest("hex")}`;
}

export function authenticateArtifact<T extends Record<string, unknown>>(target: string, value: T): T & { authentication: ArtifactAuthentication } {
  const key = authenticationKey();
  return {
    ...unsigned(value),
    authentication: {
      scheme: "hmac-sha256",
      key_id: artifactAuthenticationKeyId,
      digest: digestFor(key, target, value),
    },
  } as T & { authentication: ArtifactAuthentication };
}

export function verifyArtifactAuthentication(target: string, value: Record<string, unknown>, label: string): void {
  const authentication = value.authentication;
  if (!authentication || typeof authentication !== "object" || Array.isArray(authentication)) throw new Error(`${label} is not authenticated by this RepoRook repository`);
  const auth = authentication as Record<string, unknown>;
  if (auth.scheme !== "hmac-sha256" || typeof auth.key_id !== "string" || !/^sha256:[a-f0-9]{64}$/.test(auth.key_id)
    || typeof auth.digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(auth.digest)) {
    throw new Error(`${label} authentication metadata is invalid`);
  }
  const key = authenticationKey();
  const expectedDigest = digestFor(key, target, value);
  const keyMatches = timingSafeEqual(Buffer.from(auth.key_id), Buffer.from(artifactAuthenticationKeyId));
  const digestMatches = timingSafeEqual(Buffer.from(auth.digest), Buffer.from(expectedDigest));
  if (!keyMatches || !digestMatches) throw new Error(`${label} was not produced by this RepoRook repository or has been modified`);
}
