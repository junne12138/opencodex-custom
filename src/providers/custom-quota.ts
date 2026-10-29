import { open } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { providerQuotaQueryConfigError } from "../config/provider-validation";
import { providerOutboundGet, providerOutboundPost, providerRedirectError } from "../lib/provider-outbound";
import type { OcxProviderConfig, ProviderQuotaQueryValue } from "../types";
import type { ProviderQuota } from "./quota-types";
import {
  asRecord,
  normalizePercent,
  normalizeResetAt,
  QUOTA_JSON_READ_FAILURE,
  readQuotaJson,
  toFiniteNumber,
} from "./quota-wire";

const MAX_CREDENTIAL_FILE_BYTES = 64 * 1024;
const PATH_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;

export type CustomQuotaProbeResult =
  | { kind: "quota"; quota: ProviderQuota }
  | { kind: "terminal" }
  | null;

function dotPath(value: unknown, path: string | undefined): unknown {
  if (path === undefined) return value;
  let current = value;
  for (const segment of path.split(".")) {
    if (!PATH_SEGMENT_PATTERN.test(segment)) return undefined;
    const record = asRecord(current);
    if (!record || !Object.hasOwn(record, segment)) return undefined;
    current = record[segment];
  }
  return current;
}

function credentialPath(path: string): string | null {
  if (path.startsWith("~/")) return join(homedir(), path.slice(2));
  return isAbsolute(path) ? path : null;
}

async function readCredentialFile(path: string | undefined): Promise<Record<string, unknown> | null> {
  if (!path) return null;
  const resolved = credentialPath(path);
  if (!resolved) return null;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(resolved, "r");
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > MAX_CREDENTIAL_FILE_BYTES) return null;
    if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) return null;
    const bytes = Buffer.alloc(MAX_CREDENTIAL_FILE_BYTES + 1);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    if (bytesRead <= 0 || bytesRead > MAX_CREDENTIAL_FILE_BYTES) return null;
    return asRecord(JSON.parse(bytes.subarray(0, bytesRead).toString("utf8")));
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function scalar(value: unknown): string | number | boolean | null | undefined {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function resolveValue(
  source: ProviderQuotaQueryValue,
  credentials: Record<string, unknown> | null,
): string | number | boolean | null | undefined {
  const direct = scalar(source);
  if (direct !== undefined) return direct;
  const reference = asRecord(source);
  if (!reference) return undefined;
  if (typeof reference.$credential === "string") return scalar(dotPath(credentials, reference.$credential));
  if (typeof reference.$env === "string") return process.env[reference.$env];
  return undefined;
}

function amountsFromResponse(
  root: unknown,
  response: NonNullable<OcxProviderConfig["quotaQuery"]>["response"],
): { limit?: number; used?: number; remaining?: number; percent: number } | null {
  const limit = toFiniteNumber(dotPath(root, response.limit));
  let used = toFiniteNumber(dotPath(root, response.used));
  let remaining = toFiniteNumber(dotPath(root, response.remaining));
  if (limit !== undefined && used === undefined && remaining !== undefined) used = limit - remaining;
  if (limit !== undefined && remaining === undefined && used !== undefined) remaining = limit - used;
  const mappedPercent = normalizePercent(dotPath(root, response.percent));
  const derivedPercent = limit !== undefined && limit > 0 && used !== undefined
    ? normalizePercent((used / limit) * 100)
    : undefined;
  const percent = mappedPercent ?? derivedPercent;
  if (percent === undefined) return null;
  if (limit !== undefined && (!Number.isFinite(limit) || limit <= 0)) return null;
  if (used !== undefined && (!Number.isFinite(used) || used < 0)) return null;
  // Signed balances represent overage; keep the debt while normalizePercent caps the bar.
  if (remaining !== undefined && !Number.isFinite(remaining)) return null;
  return {
    ...(limit !== undefined ? { limit } : {}),
    ...(used !== undefined ? { used } : {}),
    ...(remaining !== undefined ? { remaining } : {}),
    percent,
  };
}

function quotaFromResponse(provider: OcxProviderConfig, body: unknown): ProviderQuota | null {
  const query = provider.quotaQuery!;
  const root = dotPath(body, query.response.root);
  const amounts = amountsFromResponse(root, query.response);
  if (!amounts) return null;
  const resetAt = normalizeResetAt(dotPath(root, query.response.resetAt));
  const quota: ProviderQuota = { updatedAt: Date.now() };
  const window = query.window ?? "custom";
  if (window === "five-hour") {
    quota.fiveHourPercent = amounts.percent;
    if (resetAt !== undefined) quota.fiveHourResetAt = resetAt;
  } else if (window === "weekly") {
    quota.weeklyPercent = amounts.percent;
    if (resetAt !== undefined) quota.weeklyResetAt = resetAt;
  } else if (window === "monthly") {
    quota.monthlyPercent = amounts.percent;
    if (resetAt !== undefined) quota.monthlyResetAt = resetAt;
  } else {
    let label = query.label?.trim() || "Custom quota";
    if (amounts.limit !== undefined && amounts.remaining !== undefined) {
      const prefix = query.unit === "usd" ? "$" : "";
      label += ` (${prefix}${amounts.remaining.toFixed(2)} of ${prefix}${amounts.limit.toFixed(2)} remaining)`;
    }
    quota.customWindows = [{ label, percent: amounts.percent, ...(resetAt !== undefined ? { resetAt } : {}) }];
  }
  if (query.unit === "usd" && amounts.limit !== undefined && amounts.used !== undefined && amounts.remaining !== undefined) {
    quota.creditsUsd = {
      limit: amounts.limit,
      used: amounts.used,
      remaining: amounts.remaining,
      percent: amounts.percent,
    };
  }
  return quota;
}

/** Runtime authorization check; config validation alone is never trusted before sending credentials. */
export function customQuotaQueryEligible(provider: OcxProviderConfig): boolean {
  return providerQuotaQueryConfigError(provider.quotaQuery, provider.baseUrl) === null
    && provider.quotaQuery !== undefined;
}

export async function fetchCustomProviderQuota(
  name: string,
  provider: OcxProviderConfig,
): Promise<CustomQuotaProbeResult> {
  if (!customQuotaQueryEligible(provider)) return null;
  const query = provider.quotaQuery!;
  const credentials = await readCredentialFile(query.credentialsFile);
  if (query.credentialsFile && !credentials) return null;

  const headers: Record<string, string> = { Accept: "application/json" };
  for (const [header, source] of Object.entries(query.headers ?? {})) {
    const value = resolveValue(source, credentials);
    if (value === undefined || value === null || /[\r\n]/.test(String(value))) return null;
    headers[header] = String(value);
  }

  const timeout = query.timeoutMs ?? 8_000;
  const signal = AbortSignal.timeout(timeout);
  let response: Response;
  if ((query.method ?? "GET") === "POST") {
    const payload: Record<string, string | number | boolean | null> = {};
    for (const [field, source] of Object.entries(query.body ?? {})) {
      const value = resolveValue(source, credentials);
      if (value === undefined) return null;
      payload[field] = value;
    }
    headers["Content-Type"] ??= "application/json";
    response = await providerOutboundPost(name, provider, query.url, {
      headers,
      body: JSON.stringify(payload),
      signal,
    });
  } else {
    response = await providerOutboundGet(name, provider, query.url, { headers, signal });
  }
  if (await providerRedirectError(response, query.url)) return { kind: "terminal" };
  if (!response.ok) {
    return response.status >= 400 && response.status < 500 && response.status !== 408 && response.status !== 429
      ? { kind: "terminal" }
      : null;
  }
  const body = await readQuotaJson(response, timeout);
  if (body === QUOTA_JSON_READ_FAILURE) return null;
  const quota = quotaFromResponse(provider, body);
  return quota ? { kind: "quota", quota } : null;
}
