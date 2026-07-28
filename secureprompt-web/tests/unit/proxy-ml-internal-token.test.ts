/**
 * WS1-5 fix-round — the ML sidecar now authenticates every route it serves
 * (except /health, /ready, /metrics) via Authorization: Bearer
 * <ML_SIDECAR_INTERNAL_TOKEN>. This dashboard proxy
 * (src/app/api/proxy/ml/[...path]/route.ts) is the ONLY thing standing
 * between the browser and the sidecar, so it must attach that token on
 * every forwarded request — overwriting, never forwarding, whatever
 * Authorization header the browser session happened to send.
 *
 * `ML_BASE`/`ML_INTERNAL_TOKEN` are top-level `const`s computed from
 * `process.env` at module-import time, so each test resets the module
 * registry and re-imports after setting the env var it needs.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@/lib/auth", () => ({
  auth: vi.fn().mockResolvedValue({ user: { id: "u1" } }),
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

async function loadRouteWithToken(token: string | undefined) {
  vi.resetModules();
  if (token === undefined) {
    delete process.env.ML_SIDECAR_INTERNAL_TOKEN;
  } else {
    process.env.ML_SIDECAR_INTERNAL_TOKEN = token;
  }
  return import("@/app/api/proxy/ml/[...path]/route");
}

describe("ML sidecar proxy attaches the internal auth token", () => {
  beforeEach(() => {
    savedEnv = {};
    for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
    vi.stubGlobal("fetch", vi.fn());
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

  it("attaches Authorization: Bearer <ML_SIDECAR_INTERNAL_TOKEN> to the upstream request", async () => {
    const { POST } = await loadRouteWithToken("web-proxy-test-token");
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse({ matches: [], is_match: false }));

    const { NextRequest } = await import("next/server");
    const req = new NextRequest("http://localhost/api/proxy/ml/v1/rag-check", {
      method: "POST",
      body: JSON.stringify({ text: "hi" }),
      headers: { "content-type": "application/json" },
    });

    await POST(req, { params: Promise.resolve({ path: ["v1", "rag-check"] }) });

    expect(fetch).toHaveBeenCalledTimes(1);
    const [, init] = vi.mocked(fetch).mock.calls[0] as [unknown, RequestInit];
    const headers = init.headers as Headers;
    expect(headers.get("authorization")).toBe("Bearer web-proxy-test-token");
  });

  it("overrides a client-supplied Authorization header rather than forwarding it", async () => {
    const { POST } = await loadRouteWithToken("web-proxy-test-token");
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse({ matches: [], is_match: false }));

    const { NextRequest } = await import("next/server");
    const req = new NextRequest("http://localhost/api/proxy/ml/v1/rag-check", {
      method: "POST",
      body: JSON.stringify({ text: "hi" }),
      headers: {
        "content-type": "application/json",
        authorization: "Bearer user-session-supplied-value",
      },
    });

    await POST(req, { params: Promise.resolve({ path: ["v1", "rag-check"] }) });

    const [, init] = vi.mocked(fetch).mock.calls[0] as [unknown, RequestInit];
    const headers = init.headers as Headers;
    expect(headers.get("authorization")).toBe("Bearer web-proxy-test-token");
    expect(headers.get("authorization")).not.toContain("user-session-supplied-value");
  });

  it("still 401s unauthenticated (no dashboard session) requests before ever calling fetch", async () => {
    const { POST } = await loadRouteWithToken("web-proxy-test-token");
    const authModule = await import("@/lib/auth");
    vi.mocked(authModule.auth).mockResolvedValueOnce(null);

    const { NextRequest } = await import("next/server");
    const req = new NextRequest("http://localhost/api/proxy/ml/v1/rag-check", {
      method: "POST",
      body: JSON.stringify({ text: "hi" }),
      headers: { "content-type": "application/json" },
    });

    const resp = await POST(req, { params: Promise.resolve({ path: ["v1", "rag-check"] }) });

    expect(resp.status).toBe(401);
    expect(fetch).not.toHaveBeenCalled();
  });
});
