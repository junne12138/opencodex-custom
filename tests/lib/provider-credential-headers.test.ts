import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { providerCredentialHeaders, providerCredentialHeadersConfigError } from "../../src/lib/provider-credential-headers";
import { outboundCredentials } from "../../src/lib/outbound-credential-registry";
import { providerFetch } from "../../src/server/responses/fetch-helpers";
import { providerOutboundPost } from "../../src/lib/provider-outbound";
import { providerEditorConfigDTO, parseProviderEditorConfigDTO, providerManagementConfigError } from "../../src/server/auth-cors";
import { configSchema } from "../../src/config/schema/config-schema";
import type { OcxConfig, OcxProviderConfig } from "../../src/types";

const baseUrl = "https://gateway.example/task/one/v1";
const directories: string[] = [];
afterEach(() => { for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true }); });
function fixture(headers: Record<string, string> = { Cookie: "session=fixture-secret" }) {
  const dir = mkdtempSync(join(tmpdir(), "ocx-credential-test-"));
  directories.push(dir);
  const path = join(dir, "credentials.json");
  const save = (value: unknown) => writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
  save({ baseUrl, headers });
  const provider: OcxProviderConfig = { adapter: "openai-responses", baseUrl, authMode: "key", keyOptional: true, credentialHeadersFile: path };
  return { provider, save, path };
}

describe("scoped provider credential files", () => {
  test("loads credentials without adding them to config, registers redaction, and rereads rotations", async () => {
    const { provider, save } = fixture();
    expect((await providerCredentialHeaders(provider, `${baseUrl}/responses`)).get("cookie")).toBe("session=fixture-secret");
    expect(outboundCredentials().matches("fixture-secret")).toBe(true);
    expect(JSON.stringify(provider)).not.toContain("fixture-secret");
    save({ baseUrl, headers: { Cookie: "session=rotated-fixture" } });
    expect((await providerCredentialHeaders(provider, `${baseUrl}/responses`)).get("cookie")).toBe("session=rotated-fixture");
  });

  test("requires exact configured base and refuses cross-origin, sibling paths, traversal and cleartext", async () => {
    const { provider, save } = fixture();
    for (const target of ["https://other.example/task/one/v1/responses", "https://gateway.example/task/two/v1/responses", `${baseUrl}evil/responses`, `${baseUrl}/../outside`, `${baseUrl}/%252e%252e/outside`, baseUrl.replace("https:", "http:")]) {
      await expect(providerCredentialHeaders(provider, target)).rejects.toThrow("HTTPS scope");
    }
    save({ baseUrl: "https://gateway.example/", headers: { Cookie: "fixture" } });
    await expect(providerCredentialHeaders(provider, `${baseUrl}/responses`)).rejects.toThrow("HTTPS scope");
  });

  test("rejects malformed, oversized, missing, permissive and symlink files without exposing content", async () => {
    const { provider, save, path } = fixture();
    for (const value of [{ baseUrl, headers: { Host: "fixture" } }, { baseUrl, headers: { Cookie: "private\r\nInjected: x" } }, { baseUrl, headers: { Cookie: "a", cookie: "b" } }, { baseUrl, headers: {} }, { baseUrl, headers: { Cookie: "x".repeat(70_000) } }]) {
      save(value);
      await expect(providerCredentialHeaders(provider, `${baseUrl}/responses`)).rejects.toThrow("HTTPS scope");
    }
    writeFileSync(path, '{"Cookie":"private-malformed');
    try { await providerCredentialHeaders(provider, `${baseUrl}/responses`); throw new Error("expected refusal"); }
    catch (error) { expect(String(error)).not.toContain("private-malformed"); }
    save({ baseUrl, headers: { Cookie: "fixture" } });
    if (process.platform !== "win32") {
      chmodSync(path, 0o644);
      await expect(providerCredentialHeaders(provider, `${baseUrl}/responses`)).rejects.toThrow("HTTPS scope");
      chmodSync(path, 0o600);
      symlinkSync(path, `${path}.link`);
      await expect(providerCredentialHeaders({ ...provider, credentialHeadersFile: `${path}.link` }, `${baseUrl}/responses`)).rejects.toThrow("HTTPS scope");
    }
    await expect(providerCredentialHeaders({ ...provider, credentialHeadersFile: `${path}.missing` }, `${baseUrl}/responses`)).rejects.toThrow("HTTPS scope");
  });

  test("inference sends both credentials, keeps caller headers immutable, and refuses auth replacement before sending", async () => {
    const { provider } = fixture({ Authorization: "Bearer fixture-bearer", Cookie: "session=fixture-cookie" });
    const sent: RequestInit[] = [];
    const execute = (async (_input, init) => { sent.push(init!); return new Response("ok"); }) as typeof fetch;
    const send = providerFetch({ ...provider, fetch: execute }, undefined, { httpOnly: true });
    const headers = new Headers({ "content-type": "application/json" });
    await send(`${baseUrl}/responses`, { method: "POST", body: "{}", headers });
    expect(new Headers(sent[0]!.headers).get("cookie")).toBe("session=fixture-cookie");
    expect(new Headers(sent[0]!.headers).get("authorization")).toBe("Bearer fixture-bearer");
    expect(sent[0]!.redirect).toBe("manual");
    expect(headers.has("cookie")).toBe(false);
    await expect(send(`${baseUrl}/responses`, { headers: { authorization: "Bearer selected-key" } })).rejects.toThrow("conflicts");
    await expect(send("https://different.example/responses", {})).rejects.toThrow("HTTPS scope");
    expect(sent).toHaveLength(1);
  });

  test("connection diagnostics use the same credentials and never follow redirects", async () => {
    const { provider } = fixture();
    let captured: RequestInit | undefined;
    const response = await providerOutboundPost("fixture", { ...provider, fetch: (async (_url, init) => { captured = init; return new Response(null, { status: 302, headers: { location: "https://elsewhere.example" } }); }) as typeof fetch }, `${baseUrl}/responses`, { body: "{}" }, { resolveAddresses: async () => ["93.184.216.34"] });
    expect(response.status).toBe(302);
    expect(captured!.redirect).toBe("manual");
    expect(new Headers(captured!.headers).get("cookie")).toBe("session=fixture-secret");
  });

  test("management and persisted schema accept references and editor roundtrips preserve only the path", () => {
    const { provider } = fixture();
    expect(providerManagementConfigError("fixture", provider)).toBeNull();
    const config = { port: 10100, defaultProvider: "fixture", providers: { fixture: provider } } as OcxConfig;
    expect(configSchema.safeParse(config).success).toBe(true);
    const dto = providerEditorConfigDTO(config);
    expect(JSON.stringify(dto)).toContain(provider.credentialHeadersFile!);
    expect(JSON.stringify(dto)).not.toContain("fixture-secret");
    expect(parseProviderEditorConfigDTO(dto)).not.toHaveProperty("error");
    for (const patch of [{ credentialHeadersFile: "relative.json" }, { authMode: "forward" }, { authMode: "oauth" }, { adapter: "anthropic" }, { baseUrl: "http://gateway.example" }]) {
      const next = { ...provider, ...patch } as OcxProviderConfig;
      expect(providerCredentialHeadersConfigError(next)).not.toBeNull();
      expect(providerManagementConfigError("fixture", next)).not.toBeNull();
      expect(configSchema.safeParse({ ...config, providers: { fixture: next } }).success).toBe(false);
    }
  });
});
