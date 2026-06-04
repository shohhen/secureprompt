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
