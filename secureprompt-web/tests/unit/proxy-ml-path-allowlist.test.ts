/**
 * MR1 review finding C5 — privilege escalation through the ML proxy.
 *
 * `src/app/api/proxy/ml/[...path]/route.ts` joined `pathParts` verbatim onto
 * the sidecar base URL and attached `Authorization: Bearer
 * <ML_SIDECAR_INTERNAL_TOKEN>`. The only check was `if (!session)`. So ANY
 * dashboard session — `viewer` included — could reach EVERY sidecar route:
 *
 *   POST /api/proxy/ml/internal/model-key
 *     -> http://secureprompt-ml:8080/internal/model-key, Bearer <tok>, 200
 *
 * `/internal/model-key` is the model-IP boundary; it authenticates with
 * `hmac.compare_digest` against the SAME `ML_SIDECAR_INTERNAL_TOKEN` the
 * proxy attaches, so the proxy was handing a low-privilege dashboard user the
 * exact credential that endpoint checks. `/detect/ner`, `/detect/injection`
 * and `/embed` were likewise reachable — unmetered, unaudited and
 * un-rate-limited detection capacity that bypasses the Rust gateway entirely.
 *
 * The real callers need exactly three prefixes:
 *   - `v1/rag-check`   (semantic-search/search-form.tsx:36)
 *   - `v1/scan-file*`  (file-scan/file-scan-api.ts:12)
 *   - `v1/secure-file*`(file-scan/file-scan-api.ts:12)
 *
 * PRODUCTION FALSIFIERS for this file (each reddens it):
 *   - delete the `isAllowedMlPath` call in `forward()` -> the four
 *     "rejects ..." cases go 200/404-with-fetch and fail.
 *   - delete the `canUseScanRoutes` / viewer check -> the viewer scan cases
 *     forward and fail.
 *   - drop the `..` segment rejection -> the traversal case forwards.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { AppRole } from "@/types/next-auth";

vi.mock("@/lib/auth", () => ({
  auth: vi.fn(),
}));

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const ENV_KEYS = ["ML_SIDECAR_URL", "ML_SIDECAR_INTERNAL_TOKEN"] as const;
type EnvKey = (typeof ENV_KEYS)[number];
let savedEnv: Partial<Record<EnvKey, string | undefined>>;

async function loadRoute() {
  vi.resetModules();
  process.env.ML_SIDECAR_INTERNAL_TOKEN = "web-proxy-test-token";
  return import("@/app/api/proxy/ml/[...path]/route");
}

async function sessionAs(role: AppRole) {
  const authModule = await import("@/lib/auth");
  vi.mocked(authModule.auth).mockResolvedValue({
    user: { id: "u1", email: "u1@example.com" },
    workspaceId: "11111111-1111-1111-1111-111111111111",
    role,
    accessToken: "at",
    accessExpiresAt: 0,
    refreshExpiresAt: 0,
    expires: "2099-01-01T00:00:00.000Z",
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);
}

async function callProxy(path: string[], method: "GET" | "POST" = "POST") {
  const route = await loadRoute();
  const { NextRequest } = await import("next/server");
  const req = new NextRequest(`http://localhost/api/proxy/ml/${path.join("/")}`, {
    method,
    ...(method === "POST"
      ? { body: JSON.stringify({ text: "hi" }), headers: { "content-type": "application/json" } }
      : {}),
  });
  const handler = method === "POST" ? route.POST : route.GET;
  return handler(req, { params: Promise.resolve({ path }) });
}

describe("ML sidecar proxy path allowlist (C5)", () => {
  beforeEach(() => {
    savedEnv = {};
    for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
    vi.stubGlobal("fetch", vi.fn());
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true }));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
    for (const k of ENV_KEYS) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k];
    }
    vi.resetModules();
  });

  it("rejects /internal/model-key for an admin session and never attaches the token", async () => {
    await sessionAs("admin");
    const resp = await callProxy(["internal", "model-key"]);

    expect(resp.status).toBe(403);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects /internal/model-key for a viewer session", async () => {
    await sessionAs("viewer");
    const resp = await callProxy(["internal", "model-key"]);

    expect(resp.status).toBe(403);
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    [["detect", "ner"]],
    [["detect", "injection"]],
    [["embed"]],
    [["v1", "index-document"]],
  ])("rejects the un-allowlisted sidecar route %j", async (path) => {
    await sessionAs("admin");
    const resp = await callProxy(path as string[]);

    expect(resp.status).toBe(403);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects a `..` segment even when the visible prefix is allowlisted", async () => {
    await sessionAs("admin");
    const resp = await callProxy(["v1", "rag-check", "..", "..", "internal", "model-key"]);

    expect(resp.status).toBe(403);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects a prefix-collision path such as v1/rag-checkX", async () => {
    await sessionAs("admin");
    const resp = await callProxy(["v1", "rag-checkXinternal"]);

    expect(resp.status).toBe(403);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("still forwards v1/rag-check for a viewer (read-only search stays open)", async () => {
    await sessionAs("viewer");
    const resp = await callProxy(["v1", "rag-check"]);

    expect(resp.status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(1);
    const [target] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(String(target)).toBe("http://secureprompt-ml:8080/v1/rag-check");
  });

  it.each([
    [["v1", "scan-file", "async"]],
    [["v1", "secure-file", "async"]],
  ])("forwards %j for a developer", async (path) => {
    await sessionAs("developer");
    const resp = await callProxy(path as string[]);

    expect(resp.status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    [["v1", "scan-file", "async"]],
    [["v1", "secure-file", "async"]],
  ])("rejects %j for a viewer — scan/secure routes need a writing role", async (path) => {
    await sessionAs("viewer");
    const resp = await callProxy(path as string[]);

    expect(resp.status).toBe(403);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not forward the dashboard session cookie to the sidecar (M11)", async () => {
    await sessionAs("admin");
    const route = await loadRoute();
    const { NextRequest } = await import("next/server");
    const req = new NextRequest("http://localhost/api/proxy/ml/v1/rag-check", {
      method: "POST",
      body: JSON.stringify({ text: "hi" }),
    });
    // happy-dom's Headers drops `Cookie` at construction, so set it after.
    req.headers.set("cookie", "authjs.session-token=SECRET-JWE");
    req.headers.set("content-type", "application/json");

    await route.POST(req, { params: Promise.resolve({ path: ["v1", "rag-check"] }) });

    expect(fetch).toHaveBeenCalledTimes(1);
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Headers;
    expect(headers.get("cookie")).toBeNull();
  });
});
