/**
 * WS1-9 — the refresh token must never appear on the CLIENT-VISIBLE NextAuth
 * session. `useSession()` / `getSession()` return that object straight to
 * the browser, so anything on it is readable by page JavaScript (an XSS
 * payload, a compromised dependency, a browser extension). The refresh
 * token is long-lived (`refreshExpiresAt` can be days out); if it leaked to
 * the browser an attacker could mint fresh access tokens indefinitely.
 *
 * SCOPE OF THIS FILE: this tests `buildClientSessionFields` in
 * `src/lib/auth-refresh.ts` ONLY — the pure function that shapes an `AppJWT`
 * into the fields the NextAuth `session` callback copies onto the session
 * object. It asserts that function's output never carries a `refreshToken`
 * key or value. It does NOT exercise the `session` callback itself (the
 * wiring in `src/lib/auth.ts` that calls `buildClientSessionFields` and
 * assigns its fields onto `session.*`) — see "what actually guards the
 * callback" below for why, and what covers that gap instead.
 *
 * Why not test `auth.ts`'s `session` callback directly: importing
 * `@/lib/auth` under Vitest throws (`next-auth` pulls in `next/server`,
 * which Vitest's pure-Node-ESM resolver can't load) — confirmed by hand
 * before writing this file, and the same constraint `tests/unit/auth.test.ts`
 * works around by testing `auth-refresh.ts` exports instead of `auth.ts`
 * directly. `buildClientSessionFields` is next-auth-free by design (same
 * reason `auth-refresh.ts` exists at all — see its module doc), so it is the
 * only place this behavior can be unit tested directly.
 *
 * What actually guards the callback wiring itself (i.e. what stops a future
 * `session.refreshToken = appToken.refreshToken` from being re-added inside
 * `auth.ts`'s `session` callback), since this file cannot:
 *   1. The `Session` interface augmentation in `src/types/next-auth.d.ts`
 *      (the `AppSessionShape` it extends) has no `refreshToken` field. TS
 *      structurally rejects assigning that key to `session.*`.
 *   2. CI's `frontend` job ("Frontend build + type check" in
 *      `.github/workflows/ci.yml`) runs `pnpm exec tsc --noEmit` as its
 *      "Type check" step. Re-introducing the assignment is therefore a
 *      compile error caught in CI, not a silent runtime leak.
 * A reviewer verified both of the above by hand. This test file provides
 * defense in depth for the pure function; it is not what makes the callback
 * itself safe, and a reader should not assume it is.
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

describe("buildClientSessionFields (pure-function leak guard; the session callback wiring itself is guarded separately — see file header)", () => {
  it("never includes a refreshToken key in the fields it returns", () => {
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
