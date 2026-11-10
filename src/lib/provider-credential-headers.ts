import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import type { OcxProviderConfig } from "../types";
import { outboundCredentials } from "./outbound-credential-registry";

type CredentialProvider = Partial<Pick<OcxProviderConfig, "baseUrl" | "credentialHeadersFile" | "adapter" | "authMode">>;
const MAX_BYTES = 64 * 1024;
const ALLOWED_HEADERS = new Set(["authorization", "cookie", "x-api-key", "x-goog-api-key", "x-amz-security-token"]);
const FAILURE = "Provider credential headers unavailable or outside their configured HTTPS scope";

/** File references are editable; credential values never enter provider configuration or DTOs. */
export function providerCredentialHeadersConfigError(provider: CredentialProvider): string | null {
  const path = provider.credentialHeadersFile;
  if (path === undefined) return null;
  if (typeof path !== "string" || !path || path.length > 4096 || /[\x00-\x1f\x7f]/.test(path)
    || !(path.startsWith("~/") || isAbsolute(path))) {
    return "credentialHeadersFile must be an absolute path or start with ~/";
  }
  if (provider.adapter !== "openai-responses" || (provider.authMode !== undefined && provider.authMode !== "key")) {
    return "credentialHeadersFile requires the openai-responses adapter with key authentication";
  }
  try { scopedUrl(provider.baseUrl); } catch { return "credentialHeadersFile requires an HTTPS baseUrl"; }
  return null;
}

function scopedUrl(value: unknown): URL {
  if (typeof value !== "string") throw new Error(FAILURE);
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash
    || /[\\\x00-\x20]/.test(value) || /%(?:2f|5c|2e|25)/i.test(url.pathname)) throw new Error(FAILURE);
  return url;
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

/** Read once per physical send, bounded and fail closed; do not follow credential-file symlinks. */
export async function providerCredentialHeaders(provider: CredentialProvider, destination: string): Promise<Headers> {
  let file: Awaited<ReturnType<typeof open>> | undefined;
  try {
    if (!provider.credentialHeadersFile || providerCredentialHeadersConfigError(provider)) throw new Error(FAILURE);
    const path = provider.credentialHeadersFile.startsWith("~/")
      ? join(homedir(), provider.credentialHeadersFile.slice(2)) : provider.credentialHeadersFile;
    file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > MAX_BYTES
      || (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()))) throw new Error(FAILURE);
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
    if (bytesRead < 1 || bytesRead > MAX_BYTES) throw new Error(FAILURE);
    const value: unknown = JSON.parse(buffer.subarray(0, bytesRead).toString("utf8"));
    if (!plainRecord(value) || Object.keys(value).some(key => key !== "baseUrl" && key !== "headers")
      || !plainRecord(value.headers)) throw new Error(FAILURE);
    const scope = scopedUrl(value.baseUrl);
    const configured = scopedUrl(provider.baseUrl);
    const target = scopedUrl(destination);
    const prefix = scope.pathname.replace(/\/+$/, "");
    if (scope.origin !== configured.origin || scope.pathname.replace(/\/+$/, "") !== configured.pathname.replace(/\/+$/, "")
      || scope.origin !== target.origin || !(target.pathname === prefix || target.pathname.startsWith(`${prefix}/`))) throw new Error(FAILURE);
    const headers = new Headers();
    for (const [name, secret] of Object.entries(value.headers)) {
      const normalized = name.toLowerCase();
      if (!ALLOWED_HEADERS.has(normalized) || headers.has(normalized) || typeof secret !== "string"
        || !secret || secret.length > 16_384 || /[^\x20-\x7e]/.test(secret)) throw new Error(FAILURE);
      headers.set(normalized, secret);
    }
    if (![...headers].length) throw new Error(FAILURE);
    outboundCredentials().remember(headers);
    return headers;
  } catch {
    // Never surface JSON parse errors, filesystem paths or secret-bearing header values.
    throw new Error(FAILURE);
  } finally {
    await file?.close().catch(() => undefined);
  }
}

/** Credential files cannot silently replace an already selected key or provider-owned header. */
export function mergeProviderCredentialHeaders(target: Headers, credentials: Headers): void {
  for (const [name, value] of credentials) {
    if (target.has(name)) throw new Error("Provider credential header conflicts with existing authentication");
    target.set(name, value);
  }
}
