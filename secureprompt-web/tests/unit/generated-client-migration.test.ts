/**
 * WS6-4 — the data hooks must go through the generated OpenAPI client, and
 * doing so must not quietly change what a caller sees on an error.
 *
 * Two halves:
 *
 *   1. `unwrap()` parity. `apiFetch` throws a typed `ApiError` carrying
 *      `.status` and `.code`; `openapi-fetch` throws nothing at all and
 *      returns `{ data, error, response }`. Migrating a hook naively turns
 *      every failure into either a silent `undefined` or a bare
 *      `new Error("Failed to fetch X")` — which is what the one
 *      already-migrated hook (`use-analytics`) does today, and it is why
 *      `license-client.tsx`'s `err instanceof ApiError && err.status === 400`
 *      and `(dashboard)/error.tsx`'s `error instanceof ApiError` could not
 *      survive the migration. These tests pin the parity BEFORE the hooks
 *      move.
 *
 *   2. The migration itself, checked by reading the hooks directory rather
 *      than a list. An 11th hook is covered the moment it is added — the same
 *      shape as `rls_call_site_guard` reading `pg_class` on the Rust side.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

vi.mock("next-auth/react", () => ({
  getSession: vi.fn().mockResolvedValue(null),
  signOut: vi.fn(),
}));
vi.mock("@/lib/auth", () => ({
  auth: vi.fn().mockResolvedValue(null),
}));

import { ApiError, NetworkError } from "@/lib/api-fetch";
import { makeApiClient, unwrap } from "@/lib/api-client";

const HOOKS_DIR = join(process.cwd(), "src/lib/hooks");

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// ── 1. unwrap() parity with apiFetch ─────────────────────────────────────────

describe("unwrap() — the error contract apiFetch callers already depend on", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("returns the parsed body on 200", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      jsonResponse(200, [{ id: "a", name: "k" }]),
    );
    const client = makeApiClient();
    const out = await unwrap(await client.GET("/v1/keys"));
    expect(out).toEqual([{ id: "a", name: "k" }]);
  });

  it("returns undefined on 204 rather than throwing", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response(null, { status: 204 }));
    const client = makeApiClient();
    await expect(
      unwrap(
        await client.DELETE("/v1/keys/{id}", { params: { path: { id: "x" } } }),
      ),
    ).resolves.toBeUndefined();
  });

  it("throws ApiError — not a bare Error — carrying status and code", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      jsonResponse(403, {
        error: { message: "Insufficient role", code: "forbidden" },
      }),
    );
    const client = makeApiClient();
    const err: unknown = await unwrap(await client.GET("/v1/keys")).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(403);
    expect((err as ApiError).code).toBe("forbidden");
    expect((err as ApiError).message).toBe("Insufficient role");
  });

  it("falls back to http_<status> when the body is not an error envelope", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response("gateway blew up", { status: 502 }),
    );
    const client = makeApiClient();
    const err: unknown = await unwrap(await client.GET("/v1/keys")).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(502);
    expect((err as ApiError).code).toBe("http_502");
  });

  it("dispatches sp:budget-exceeded on 402, like apiFetch does", async () => {
    // Both `components/providers.tsx` and `components/layout/topbar.tsx`
    // listen for this event. A migration that dropped it would silently
    // remove the budget banner.
    vi.mocked(fetch).mockResolvedValueOnce(
      jsonResponse(402, {
        error: { message: "Budget exhausted", code: "budget_exceeded" },
      }),
    );
    const seen: CustomEvent[] = [];
    const handler = (e: Event) => seen.push(e as CustomEvent);
    window.addEventListener("sp:budget-exceeded", handler);
    try {
      const client = makeApiClient();
      const err: unknown = await unwrap(await client.GET("/v1/keys")).catch(
        (e: unknown) => e,
      );
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(402);
      expect(seen).toHaveLength(1);
    } finally {
      window.removeEventListener("sp:budget-exceeded", handler);
    }
  });

  it("signs out on 401, like apiFetch does", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      jsonResponse(401, { error: { message: "nope", code: "unauthorized" } }),
    );
    const { signOut } = await import("next-auth/react");
    const client = makeApiClient();
    await unwrap(await client.GET("/v1/keys")).catch(() => undefined);
    expect(signOut).toHaveBeenCalled();
  });

  it("turns a transport failure into NetworkError, like apiFetch does", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new TypeError("Failed to fetch"));
    const client = makeApiClient();
    const err: unknown = await client
      .GET("/v1/keys")
      .then(unwrap)
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
  });

  it("preserves the Content-Type openapi-fetch set", async () => {
    // Regression, found by probe while migrating: openapi-fetch calls the
    // custom fetch as `fetch(request)` with the header already on the
    // Request, and `fetch(request, { headers })` REPLACES the header list
    // rather than merging. The old object-literal spread therefore dropped
    // `Content-Type: application/json` from every request with a body, which
    // axum's `Json<T>` extractor answers with 415. It was invisible until
    // this workstream because the only caller was `use-analytics`, four GETs.
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, {}));
    const client = makeApiClient({ bearer: "tok" });
    await client.POST("/v1/auth/token", {
      body: { email: "a@b.test", password: "pw" },
    });
    const [input, init] = vi.mocked(fetch).mock.calls[0] as [
      Request,
      RequestInit | undefined,
    ];
    // Premise: openapi-fetch really does hand us a Request that already
    // carries the header — otherwise this test proves nothing about merging.
    expect(input).toBeInstanceOf(Request);
    expect(input.headers.get("content-type")).toBe("application/json");
    // What the platform would actually send.
    const effective = new Request(input, init);
    expect(effective.headers.get("content-type")).toBe("application/json");
    expect(effective.headers.get("authorization")).toBe("Bearer tok");
    // Bidirectional: the merge must not have dropped what it was added for.
    expect(await effective.text()).toBe(
      JSON.stringify({ email: "a@b.test", password: "pw" }),
    );
  });

  it("sends no Authorization header when bearer is explicitly null", async () => {
    // `loginStep1` runs before any session exists. Resolving one would fire a
    // second fetch at /api/auth/session on every login attempt.
    const { getSession } = await import("next-auth/react");
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, {}));
    await makeApiClient({ bearer: null }).POST("/v1/auth/token", {
      body: { email: "a@b.test", password: "pw" },
    });
    const [input, init] = vi.mocked(fetch).mock.calls[0] as [
      Request,
      RequestInit | undefined,
    ];
    expect(new Request(input, init).headers.get("authorization")).toBeNull();
    expect(getSession).not.toHaveBeenCalled();
  });

  // Positive control: the assertions above must be capable of failing. A
  // 200 must NOT produce an ApiError, or "throws ApiError" would be
  // satisfied by a function that throws unconditionally.
  it("does not throw on a successful response", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, []));
    const client = makeApiClient();
    await expect(unwrap(await client.GET("/v1/keys"))).resolves.toEqual([]);
  });
});

// ── 2. the migration, read out of the directory ──────────────────────────────

/**
 * `src/lib/twofa-api.ts` is not under `src/lib/hooks`, but `use-two-factor.ts`
 * is a thin wrapper over it and the raw `fetch` calls live there, so it is the
 * tenth subject. Named rather than globbed because it is the one file outside
 * the directory.
 */
const EXTRA_SUBJECTS = ["src/lib/twofa-api.ts"];

function hookFiles(): string[] {
  return readdirSync(HOOKS_DIR)
    .filter((f) => f.endsWith(".ts") || f.endsWith(".tsx"))
    .map((f) => join("src/lib/hooks", f));
}

function read(rel: string): string {
  return readFileSync(join(process.cwd(), rel), "utf8");
}

describe("data hooks are on the generated client", () => {
  it("finds the hooks by reading the directory, not from a list here", () => {
    // Premise assertion. If the directory scan returns nothing, every
    // assertion below passes over an empty set.
    const files = hookFiles();
    expect(files.length).toBeGreaterThanOrEqual(10);
    expect(files).toContain("src/lib/hooks/use-keys.ts");
  });

  it.each([...hookFiles(), ...EXTRA_SUBJECTS])(
    "%s does not hand-roll HTTP",
    (rel) => {
      const src = read(rel);
      expect(
        src,
        `${rel} still imports apiFetch. The generated client (makeApiClient + ` +
          `unwrap) is the only sanctioned transport for documented routes.`,
      ).not.toMatch(/from\s+["']@\/lib\/api-fetch["']/);
      expect(
        src,
        `${rel} calls fetch() directly. Every route it touches is in ` +
          `openapi.yaml, so the typed client covers it.`,
      ).not.toMatch(/(^|[^.\w])fetch\s*\(/m);
    },
  );

  it.each([...hookFiles(), ...EXTRA_SUBJECTS])(
    "%s declares no response interface of its own",
    (rel) => {
      const src = read(rel);
      // A hook may still export *parameter* types it computes itself
      // (`DateRangeParams`, filter objects). What it may not do is redeclare
      // the wire shapes — those come from api.gen.ts.
      const wireShapes = [...src.matchAll(/export interface (\w+)/g)]
        .map((m) => m[1])
        .filter((n) => /(Response|Request|Body|Row|Detail|Summary|Item)$/.test(n));
      expect(
        wireShapes,
        `${rel} redeclares wire types ${JSON.stringify(wireShapes)} that ` +
          `openapi-typescript already generates into src/types/api.gen.ts. ` +
          `Import them from there — that is the whole point of the codegen.`,
      ).toEqual([]);
    },
  );
});
