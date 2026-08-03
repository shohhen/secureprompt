/**
 * Pure-TS silent-refresh logic for the NextAuth v5 `jwt` callback.
 *
 * This module is intentionally decoupled from `next-auth` imports so it can
 * be imported by `tests/unit/auth.test.ts` under Vitest (which cannot resolve
 * Next.js' `next/server` subpath under pure Node ESM).
 *
 * Consumed by `src/lib/auth.ts`. Do NOT add any import from `next-auth` or
 * `next/*` here.
 */
import type { AppRole, AppSessionUser } from "@/types/next-auth";

/** Refresh this many seconds *before* the access token expires. */
export const REFRESH_WINDOW_SECONDS = 120;

/** Fetch signature injectable for unit tests. */
export type FetchImpl = typeof fetch;

/** Subset of the JWT payload we manage. Mirrors next-auth/jwt augmentation. */
export interface AppJWT {
  sub?: string;
  user: AppSessionUser;
  workspaceId: string;
  role: AppRole;
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: number; // unix seconds
  refreshExpiresAt: number; // unix seconds
  error?: "RefreshAccessTokenError";
}

interface RefreshTokenResponse {
  access_token: string;
  refresh_token: string;
  access_expires_at: number;
  refresh_expires_at: number;
}

/** The token/session fields the NextAuth `session` callback copies onto the
 * client-visible session object (everything except the `user.*` merge,
 * which needs the live NextAuth `session.user` default and stays in
 * `auth.ts`).
 *
 * Deliberately has NO `refreshToken` field — see `buildClientSessionFields`
 * doc below. */
export interface ClientSessionFields {
  workspaceId: string;
  role: AppRole;
  accessToken: string;
  accessExpiresAt: number;
  refreshExpiresAt: number;
  error?: "RefreshAccessTokenError";
}

/**
 * Shapes the server-side `AppJWT` into the fields the `session` callback
 * puts on the session object returned to the browser.
 *
 * SECURITY (WS1-9): `refreshToken` MUST NOT be included here. The NextAuth
 * `session` object is exactly what `useSession()` (client components) and
 * `getSession()` return — it is serialized to the browser and readable by
 * any script running on the page (XSS, a compromised npm dependency, a
 * malicious browser extension). The refresh token is long-lived
 * (`refreshExpiresAt` is typically days out, far past `accessExpiresAt`),
 * so if it ever reached client-side JS, that script could mint fresh
 * access tokens indefinitely — long after the current access token, or
 * even the user's actual browser session, should have stopped working.
 *
 * The refresh token still has to live somewhere the SERVER can reach it:
 * after sign-in it is held in the encrypted NextAuth JWT cookie (the
 * `AppJWT` this function takes as input) and is read exclusively by
 * `refreshAccessTokenIfNeeded` inside the server-side `jwt` callback
 * (`src/lib/auth.ts`), which never runs in the browser. Silent refresh
 * keeps working; it just never surfaces the token used to do it.
 *
 * SCOPE, corrected (MR1 review I9): "if it ever reached client-side JS"
 * above describes the risk this function removes, not a property the whole
 * login flow has. It reaches client-side JS exactly once, during sign-in:
 * `twofa-api.ts::loginStep1` is a browser `fetch` that reads
 * `body.refresh_token`, and the `"use client"` login form hands it to
 * `signIn("credentials", …)`. What this function guarantees is that the
 * exposure does not EXTEND across the session — which is the difference
 * between "an XSS during one form submission" and "any XSS, at any point,
 * for as long as the user is signed in". Removing the remaining single-turn
 * exposure means moving the `/v1/auth/token` exchange server-side; see the
 * note in `src/types/next-auth.d.ts` and
 * `tests/unit/refresh-token-transits-the-browser-at-login.test.ts`.
 */
export function buildClientSessionFields(token: AppJWT): ClientSessionFields {
  return {
    workspaceId: token.workspaceId,
    role: token.role,
    accessToken: token.accessToken,
    accessExpiresAt: token.accessExpiresAt,
    refreshExpiresAt: token.refreshExpiresAt,
    error: token.error,
  };
}

function apiBaseUrl(): string {
  // `refreshAccessTokenIfNeeded` runs inside the NextAuth `jwt` callback, which
  // executes SERVER-SIDE (in the web container). It must reach the API over the
  // internal compose network (`API_URL`, e.g. http://api:8080) — NOT
  // `NEXT_PUBLIC_API_URL` (http://localhost:8080), which inside the container
  // points at the web service itself, so the refresh fetch fails and the user
  // is signed out on the next request after the access token nears expiry.
  // Mirrors `auth.ts:apiBaseUrl()`; the public URL stays as a local-dev fallback.
  const url = process.env.API_URL ?? process.env.NEXT_PUBLIC_API_URL;
  if (!url) {
    throw new Error("API_URL / NEXT_PUBLIC_API_URL is not set");
  }
  return url.replace(/\/+$/, "");
}

/**
 * If the access token is close to expiring, POST /v1/auth/refresh and replace
 * the tokens. On any non-2xx or network failure, set
 * token.error = "RefreshAccessTokenError" and return the (stale) token so the
 * caller can decide to signOut().
 */
export async function refreshAccessTokenIfNeeded(
  token: AppJWT,
  fetchImpl: FetchImpl = fetch,
): Promise<AppJWT> {
  const now = Math.floor(Date.now() / 1000);
  if (token.accessExpiresAt > now + REFRESH_WINDOW_SECONDS) {
    return token;
  }

  try {
    const res = await fetchImpl(`${apiBaseUrl()}/v1/auth/refresh`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ refresh_token: token.refreshToken }),
    });

    if (!res.ok) {
      return { ...token, error: "RefreshAccessTokenError" };
    }

    const data = (await res.json()) as RefreshTokenResponse;
    return {
      ...token,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      accessExpiresAt: data.access_expires_at,
      refreshExpiresAt: data.refresh_expires_at,
      error: undefined,
    };
  } catch {
    return { ...token, error: "RefreshAccessTokenError" };
  }
}
