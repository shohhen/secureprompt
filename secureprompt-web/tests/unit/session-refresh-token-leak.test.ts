/**
 * WS1-9 — the refresh token must never appear on the CLIENT-VISIBLE NextAuth
 * session. `useSession()` / `getSession()` return that object straight to
 * the browser, so anything on it is readable by page JavaScript (an XSS
 * payload, a compromised dependency, a browser extension). The refresh
 * token is long-lived (`refreshExpiresAt` can be days out); if it leaked to
 * the browser an attacker could mint fresh access tokens indefinitely.
 *
 * `buildClientSessionFields` (src/lib/auth-refresh.ts) is the pure function
 * the real NextAuth `session` callback (src/lib/auth.ts) delegates to for
 * shaping the JWT into what lands on the session. This test snapshots its
 * output and asserts no `refreshToken` key is present. It is deliberately
 * NOT a test of `auth.ts`'s `session` callback directly: importing
 * `@/lib/auth` under Vitest throws (`next-auth` pulls in `next/server`,
 * which Vitest's pure-Node-ESM resolver can't load) — confirmed by hand
 * before writing this file. `buildClientSessionFields` is next-auth-free by
 * design (same reason `auth-refresh.ts` exists at all — see its module
 * doc), so it is the only place this behavior can be unit tested directly.
 */
import { describe, it, expect } from "vitest";
import { buildClientSessionFields, type AppJWT } from "@/lib/auth-refresh";

const NOW = Math.floor(Date.now() / 1000);

const makeToken = (overrides: Partial<AppJWT> = {}): AppJWT => ({
  sub: "user-1",
  user: { id: "user-1", email: "admin.a@fixtures.test" },
  workspaceId: "ws-1",
  role: "admin",
  accessToken: "access-fixture-value",
  refreshToken: "refresh-fixture-SECRET-value",
  accessExpiresAt: NOW + 900,
  refreshExpiresAt: NOW + 3600 * 24 * 30,
  ...overrides,
});

describe("buildClientSessionFields (session-payload leak guard)", () => {
  it("never includes a refreshToken key in the client-visible session fields", () => {
    const fields = buildClientSessionFields(makeToken());

    expect(fields).not.toHaveProperty("refreshToken");
    expect(Object.keys(fields).sort()).toMatchInlineSnapshot(`
      [
        "accessExpiresAt",
        "accessToken",
        "error",
        "refreshExpiresAt",
        "role",
        "workspaceId",
      ]
    `);
  });

  it("does not leak the refresh token's value anywhere in the serialized payload", () => {
    const fields = buildClientSessionFields(makeToken());

    // Belt-and-suspenders: even if a future refactor renames the key,
    // the secret VALUE must not survive serialization either.
    expect(JSON.stringify(fields)).not.toContain("refresh-fixture-SECRET-value");
  });

  it("still carries the access token and expiry fields the dashboard needs", () => {
    const fields = buildClientSessionFields(makeToken());

    expect(fields.accessToken).toBe("access-fixture-value");
    expect(fields.workspaceId).toBe("ws-1");
    expect(fields.role).toBe("admin");
    expect(fields.accessExpiresAt).toBe(NOW + 900);
    expect(fields.refreshExpiresAt).toBe(NOW + 3600 * 24 * 30);
  });
});
