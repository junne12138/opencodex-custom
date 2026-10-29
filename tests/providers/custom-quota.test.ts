import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getDefaultConfig, validateConfigCandidate } from "../../src/config";
import { providerQuotaQueryConfigError } from "../../src/config/provider-validation";
import {
  clearProviderQuotaCache,
  fetchProviderApiKeyQuotas,
  fetchProviderQuotaReports,
  providerApiKeyQuotaMode,
} from "../../src/providers/quota";
import { providerManagementConfigError } from "../../src/server/auth-cors";
import type { OcxConfig } from "../../src/types";
import { removeTreeWithRetry } from "../helpers/remove-tree";

let taskDir: string;

function compassConfig(fetch: typeof globalThis.fetch): OcxConfig {
  const credentialsFile = join(taskDir, "compass.json");
  writeFileSync(credentialsFile, JSON.stringify({
    project_id: "project-fixture",
    sso_session_cookie: "session-fixture",
  }), { mode: 0o600 });
  return {
    defaultProvider: "compass",
    providers: {
      compass: {
        adapter: "anthropic",
        authMode: "key",
        baseUrl: "https://compass.llm.shopee.io/compass-api/v1",
        apiKey: "gateway-fixture",
        fetch,
        quotaQuery: {
          url: "https://compass.llm.shopee.io/api/v1/cqp/ccswitch/monthly_usage",
          method: "POST",
          credentialsFile,
          headers: { Cookie: { $credential: "sso_session_cookie" } },
          body: { project_id: { $credential: "project_id" } },
          response: {
            root: "data",
            limit: "total_amount",
            used: "usage",
            remaining: "balance",
          },
          window: "monthly",
          unit: "usd",
          label: "Compass monthly",
        },
      },
    },
  } as OcxConfig;
}

beforeEach(() => {
  taskDir = mkdtempSync(join(tmpdir(), "ocx-custom-quota-"));
  clearProviderQuotaCache();
});

afterEach(() => {
  clearProviderQuotaCache();
  removeTreeWithRetry(taskDir);
});

describe("custom provider quota", () => {
  test("maps a credential-backed POST response into monthly and credit quota", async () => {
    const seen: Array<{ url: string; method?: string; redirect?: RequestRedirect; headers?: Record<string, string>; body?: string }> = [];
    const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      seen.push({
        url: String(input),
        method: init?.method,
        redirect: init?.redirect,
        headers: init?.headers as Record<string, string> | undefined,
        body: String(init?.body),
      });
      return Response.json({
        data: { total_amount: 350, usage: 212.67, balance: 137.33 },
      });
    }) as typeof globalThis.fetch;

    const result = await fetchProviderQuotaReports(compassConfig(fetch), true);

    expect(result.reports).toHaveLength(1);
    expect(result.reports[0]).toMatchObject({
      provider: "compass",
      source: "custom:quota-query",
      quota: {
        monthlyPercent: 60.76285714285714,
        creditsUsd: {
          limit: 350,
          used: 212.67,
          remaining: 137.33,
          percent: 60.76285714285714,
        },
      },
    });
    expect(seen).toEqual([{
      url: "https://compass.llm.shopee.io/api/v1/cqp/ccswitch/monthly_usage",
      method: "POST",
      redirect: "manual",
      headers: {
        Accept: "application/json",
        Cookie: "session-fixture",
        "Content-Type": "application/json",
        "User-Agent": "opencodex",
      },
      body: JSON.stringify({ project_id: "project-fixture" }),
    }]);
    expect(JSON.stringify(result)).not.toContain("session-fixture");
    expect(JSON.stringify(result)).not.toContain("project-fixture");
  });

  test.each([
    { total_amount: 200, usage: 200.06, balance: -0.06 },
    { total_amount: 200, usage: 200.06 },
    { total_amount: 200, balance: -0.06 },
  ])("keeps overdrawn balances visible: %j", async data => {
    const config = compassConfig((async () => Response.json({ data })) as typeof globalThis.fetch);
    const result = await fetchProviderQuotaReports(config, true);

    expect(result.reports).toHaveLength(1);
    const quota = result.reports[0]!.quota;
    expect(quota.monthlyPercent).toBe(100);
    expect(quota.creditsUsd?.limit).toBe(200);
    expect(quota.creditsUsd?.used).toBeCloseTo(200.06);
    expect(quota.creditsUsd?.remaining).toBeCloseTo(-0.06);
    expect(quota.creditsUsd?.percent).toBe(100);
  });

  test("supports environment-backed GET probes and provider-specific windows", async () => {
    const previous = process.env.OCX_QUOTA_FIXTURE;
    process.env.OCX_QUOTA_FIXTURE = "env-fixture";
    try {
      const fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
        expect(init?.headers).toMatchObject({ "X-Quota-Token": "env-fixture" });
        return Response.json({ usage: { percent: 17, resets_at: "2026-10-01T00:00:00.000Z" } });
      }) as typeof globalThis.fetch;
      const config = compassConfig(fetch);
      config.providers.compass!.quotaQuery = {
        url: "https://compass.llm.shopee.io/api/v1/quota",
        headers: { "X-Quota-Token": { $env: "OCX_QUOTA_FIXTURE" } },
        response: { root: "usage", percent: "percent", resetAt: "resets_at" },
        window: "custom",
        label: "Compass allowance",
      };

      const result = await fetchProviderQuotaReports(config, true);

      expect(result.reports[0]?.quota.customWindows).toEqual([{
        label: "Compass allowance",
        percent: 17,
        resetAt: Date.parse("2026-10-01T00:00:00.000Z"),
      }]);
    } finally {
      if (previous === undefined) delete process.env.OCX_QUOTA_FIXTURE;
      else process.env.OCX_QUOTA_FIXTURE = previous;
    }
  });

  test("invalidates the provider cache when the response mapping changes", async () => {
    let fetchCalls = 0;
    const fetch = (async () => {
      fetchCalls += 1;
      return Response.json({ data: { total_amount: 10, usage: 2, spent: 5, balance: 8 } });
    }) as typeof globalThis.fetch;
    const config = compassConfig(fetch);

    expect((await fetchProviderQuotaReports(config)).reports[0]?.quota.monthlyPercent).toBe(20);
    config.providers.compass!.quotaQuery!.response.used = "spent";
    expect((await fetchProviderQuotaReports(config)).reports[0]?.quota.monthlyPercent).toBe(50);
    expect(fetchCalls).toBe(2);
  });

  test("keeps provider-level custom quota out of per-API-key account rows", async () => {
    const config = compassConfig(async () => Response.json({}));
    const provider = config.providers.compass!;

    expect(providerApiKeyQuotaMode("compass", provider)).toBe("unsupported");
    expect(await fetchProviderApiKeyQuotas(config, "compass", true)).toEqual([]);
  });

  test("rejects unsafe destinations, paths, headers, and unknown fields", () => {
    const base = {
      url: "https://compass.llm.shopee.io/api/v1/quota",
      response: { percent: "data.percent" },
    };
    expect(providerQuotaQueryConfigError(base, "https://compass.llm.shopee.io/v1")).toBeNull();
    expect(providerQuotaQueryConfigError({ ...base, url: "https://example.test/quota" }, "https://compass.llm.shopee.io/v1"))
      .toContain("same origin");
    expect(providerQuotaQueryConfigError({ ...base, credentialsFile: "credentials.json" }, "https://compass.llm.shopee.io/v1"))
      .toContain("absolute");
    expect(providerQuotaQueryConfigError({ ...base, headers: { Host: { $env: "HOST_OVERRIDE" } } }, "https://compass.llm.shopee.io/v1"))
      .toContain("invalid");
    expect(providerQuotaQueryConfigError({ ...base, responsePath: "data" }, "https://compass.llm.shopee.io/v1"))
      .toContain("unexpected fields");
  });

  test("passes persisted-config and management write validation", () => {
    const provider = compassConfig(async () => Response.json({})).providers.compass!;
    delete provider.fetch;
    const config = getDefaultConfig();
    config.providers.compass = provider;

    expect(validateConfigCandidate(config).ok).toBe(true);
    expect(providerManagementConfigError("compass", provider)).toBeNull();
  });

  test("requires a credential file whenever a request references one", () => {
    const error = providerQuotaQueryConfigError({
      url: "https://compass.llm.shopee.io/api/v1/quota",
      headers: { Cookie: { $credential: "cookie" } },
      response: { percent: "data.percent" },
    }, "https://compass.llm.shopee.io/v1");
    expect(error).toContain("credentialsFile is required");
  });

  test("does not read a credential file that is accessible to other users", async () => {
    if (process.platform === "win32") return;
    let fetchCalls = 0;
    const fetch = (async () => {
      fetchCalls += 1;
      return Response.json({ data: { total_amount: 10, usage: 1, balance: 9 } });
    }) as typeof globalThis.fetch;
    const config = compassConfig(fetch);
    chmodSync(config.providers.compass!.quotaQuery!.credentialsFile!, 0o644);

    expect((await fetchProviderQuotaReports(config, true)).reports).toEqual([]);
    expect(fetchCalls).toBe(0);
  });

  test("does not read a credential file larger than the fixed bound", async () => {
    let fetchCalls = 0;
    const fetch = (async () => {
      fetchCalls += 1;
      return Response.json({ data: { total_amount: 10, usage: 1, balance: 9 } });
    }) as typeof globalThis.fetch;
    const config = compassConfig(fetch);
    writeFileSync(config.providers.compass!.quotaQuery!.credentialsFile!, "x".repeat(64 * 1024 + 1), { mode: 0o600 });

    expect((await fetchProviderQuotaReports(config, true)).reports).toEqual([]);
    expect(fetchCalls).toBe(0);
  });

  test("treats authentication failures as terminal and suppresses stale quota", async () => {
    let status = 200;
    const fetch = (async () => status === 200
      ? Response.json({ data: { total_amount: 10, usage: 2, balance: 8 } })
      : new Response("unauthorized", { status })) as typeof globalThis.fetch;
    const config = compassConfig(fetch);
    expect((await fetchProviderQuotaReports(config, true)).reports).toHaveLength(1);
    status = 401;
    expect((await fetchProviderQuotaReports(config, true)).reports).toEqual([]);
  });
});
