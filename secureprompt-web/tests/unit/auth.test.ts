/**
 * Unit tests for NextAuth v5 `jwt` callback silent-refresh logic.
 * Covers VALIDATION 5-01-02 (silent refresh) and 5-02-B done criteria.
 *
 * We inject a fake `fetch` into `refreshAccessTokenIfNeeded` so no network
 * is touched. The function returns the (possibly refreshed) JWT payload.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  refreshAccessTokenIfNeeded,
  REFRESH_WINDOW_SECONDS,
  type AppJWT,
} from "@/lib/auth-refresh";

const NOW = Math.floor(Date.now() / 1000);

const makeToken = (overrides: Partial<AppJWT> = {}): AppJWT => ({
  sub: "user-1",
  user: { id: "user-1", email: "admin.a@fixtures.test" },
  workspaceId: "ws-1",
  role: "admin",
  accessToken: "access-old",
  refreshToken: "refresh-old",
  accessExpiresAt: NOW + 900,
  refreshExpiresAt: NOW + 3600,
  ...overrides,
});

describe("refreshAccessTokenIfNeeded", () => {
  beforeEach(() => {
    vi.stubEnv("NEXT_PUBLIC_API_URL", "http://localhost:8080");
  });

  it("returns token unchanged when access token is still fresh", async () => {
    const token = makeToken({ accessExpiresAt: NOW + 900 });
    const fetchImpl = vi.fn();

    const out = await refreshAccessTokenIfNeeded(token, fetchImpl);

    expect(out.accessToken).toBe("access-old");
    expect(out.refreshToken).toBe("refresh-old");
    expect(out.error).toBeUndefined();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("refreshes access token when expiry is within the refresh window", async () => {
    const token = makeToken({
      accessExpiresAt: NOW + REFRESH_WINDOW_SECONDS - 10,
    });

    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: "access-NEW",
          refresh_token: "refresh-NEW",
          access_expires_at: NOW + 900,
          refresh_expires_at: NOW + 3600,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );

    const out = await refreshAccessTokenIfNeeded(token, fetchImpl);

    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = fetchImpl.mock.calls[0];
    expect(String(url)).toContain("/v1/auth/refresh");
    expect((init as RequestInit)?.method).toBe("POST");
    const bodyJson = JSON.parse((init as RequestInit)?.body as string);
    expect(bodyJson).toEqual({ refresh_token: "refresh-old" });

    expect(out.accessToken).toBe("access-NEW");
    expect(out.refreshToken).toBe("refresh-NEW");
    expect(out.error).toBeUndefined();
  });

  it("sets RefreshAccessTokenError when refresh endpoint returns 401", async () => {
    const token = makeToken({ accessExpiresAt: NOW + 30 });

    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: "invalid_grant" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
    );

    const out = await refreshAccessTokenIfNeeded(token, fetchImpl);

    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(out.error).toBe("RefreshAccessTokenError");
    // stale tokens are preserved so the caller can decide to signOut
    expect(out.accessToken).toBe("access-old");
  });

  it("sets RefreshAccessTokenError when refresh endpoint throws (network)", async () => {
    const token = makeToken({ accessExpiresAt: NOW + 30 });
    const fetchImpl = vi.fn().mockRejectedValue(new TypeError("network down"));

    const out = await refreshAccessTokenIfNeeded(token, fetchImpl);

    expect(out.error).toBe("RefreshAccessTokenError");
  });
});
