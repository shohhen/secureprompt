/**
 * MR1 review I9 — the refresh token DOES reach client-side JavaScript, once,
 * during sign-in. This file pins that so the comments that describe it cannot
 * drift back into claiming otherwise.
 *
 * Two comments used to assert the opposite: `src/types/next-auth.d.ts` said
 * the refresh token "must never leave the server ... it lives only in the
 * encrypted JWT cookie", and `src/lib/auth-refresh.ts` reasoned from "if it
 * ever reached client-side JS". Both are now corrected, and a corrected
 * comment with nothing holding it true is how the first one got written.
 *
 * WHAT IS BEING PINNED, precisely: `loginStep1` is a plain browser `fetch`
 * helper in a module whose own header says it is "called from client
 * components (login form, challenge/enroll screens, settings page)", and it
 * returns the refresh token to its caller. `src/app/(auth)/login/login-form.tsx`
 * is `"use client"` and passes exactly that value to
 * `signIn("credentials", …)`. So the token is materialised in page JS on
 * every sign-in and POSTed through NextAuth's credentials endpoint into the
 * cookie — it ends up server-side, it does not start there.
 *
 * WHY THIS IS A TEST AND NOT A COMMENT: if the `/v1/auth/token` exchange is
 * ever moved into a server action or route handler — the real fix, which
 * would also have to move the 2FA challenge and enroll flows — `loginStep1`
 * stops handing a refresh token to its caller and this file reddens. That is
 * the moment the two comments should be STRENGTHENED, and this failure is
 * what will say so.
 *
 * NOT a leak assertion. `tests/unit/build-client-session-fields.test.ts`
 * covers the property that actually holds: the token is absent from the
 * client-visible session for the lifetime of the session. This file covers
 * the boundary of that property.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { loginStep1 } from "@/lib/twofa-api";

const REFRESH = "refresh-token-VISIBLE-IN-BROWSER-JS";

afterEach(() => {
  vi.unstubAllGlobals();
});

function stubTokenResponse(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      status: 200,
      json: async () => ({
        access_token: "access-fixture",
        refresh_token: REFRESH,
        access_expires_at: 1,
        refresh_expires_at: 2,
        user: { id: "u1", email: "a@b.test" },
        workspace_id: "ws-1",
        role: "admin",
      }),
    })),
  );
}

describe("the refresh token transits the browser during sign-in (MR1 I9)", () => {
  it("loginStep1 hands the refresh token back to its caller, in the browser", async () => {
    stubTokenResponse();

    const result = await loginStep1("a@b.test", "password");

    // Premise: the happy path is what ran. If this ever becomes "error" the
    // assertion below would be checking the shape of a failure.
    expect(result.kind).toBe("tokens");

    if (result.kind !== "tokens") return;

    expect(result.tokens.refreshToken).toBe(REFRESH);
  });

  it("loginStep1 reaches the gateway directly from the page, not through a server route", async () => {
    stubTokenResponse();

    await loginStep1("a@b.test", "password");

    // The second half of why the token is in page JS: this helper talks to
    // the gateway's `/v1/auth/token` itself over `NEXT_PUBLIC_API_URL`. A
    // server-side exchange would post to a same-origin route handler or run
    // as a server action, and would not call `fetch` with the public API
    // base at all.
    const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toMatch(/\/v1\/auth\/token$/);
  });
});
