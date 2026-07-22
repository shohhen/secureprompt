/**
 * NextAuth v5 (next-auth@beta) configuration.
 *
 * - Credentials provider → POST {NEXT_PUBLIC_API_URL}/v1/auth/token
 * - session.strategy = "jwt" (REQUIRED — Credentials is incompatible with
 *   database sessions; 05-PATTERNS Pitfall #7)
 * - Silent refresh: the jwt callback refreshes the access token 120 s before
 *   expiry, replay-detection on the refresh endpoint surfaces as
 *   token.error = "RefreshAccessTokenError" so the client can signOut().
 *
 * The silent-refresh function lives in `./auth-refresh` (pure TS, no
 * `next-auth` / `next/*` imports) so it can be unit-tested under Vitest
 * without pulling Next.js runtime modules into the test graph.
 */
import NextAuth, { type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import type { AppRole } from "@/types/next-auth";
import {
  refreshAccessTokenIfNeeded,
  type AppJWT,
  type FetchImpl,
} from "./auth-refresh";

// Re-export the pure-TS helpers so downstream callers and tests can
// continue to `import { refreshAccessTokenIfNeeded, AppJWT } from "@/lib/auth"`.
export {
  refreshAccessTokenIfNeeded,
  REFRESH_WINDOW_SECONDS,
} from "./auth-refresh";
export type { AppJWT, FetchImpl } from "./auth-refresh";

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  access_expires_at: number;
  refresh_expires_at: number;
  user?: { id: string; email: string };
  workspace_id?: string;
  role?: AppRole;
}

function apiBaseUrl(): string {
  // `authorize` runs server-side (NextAuth credentials callback). Prefer the
  // internal `API_URL` (e.g. http://api:8080 in docker-compose) so the call
  // stays inside the compose network; fall back to the public URL for local
  // dev where only `NEXT_PUBLIC_API_URL` is set.
  const url = process.env.API_URL ?? process.env.NEXT_PUBLIC_API_URL;
  if (!url) {
    throw new Error("API_URL / NEXT_PUBLIC_API_URL is not set");
  }
  return url.replace(/\/+$/, "");
}

/**
 * Call the Rust gateway's /v1/auth/token endpoint with email+password.
 * Returns a NextAuth User on success, null on invalid credentials.
 */
async function authorizeWithBackend(
  email: string,
  password: string,
  fetchImpl: FetchImpl = fetch,
) {
  try {
    const res = await fetchImpl(`${apiBaseUrl()}/v1/auth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as TokenResponse;
    if (!data.access_token || !data.refresh_token) return null;
    return {
      id: data.user?.id ?? email,
      email: data.user?.email ?? email,
      workspaceId: data.workspace_id ?? "",
      role: (data.role ?? "viewer") as AppRole,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      accessExpiresAt: data.access_expires_at,
      refreshExpiresAt: data.refresh_expires_at,
    };
  } catch {
    return null;
  }
}

export const authConfig: NextAuthConfig = {
  trustHost: true,
  session: { strategy: "jwt" },
  pages: { signIn: "/login" },
  providers: [
    Credentials({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
        // --- Pre-obtained-tokens path (2FA flow; see docs/superpowers/
        // plans/2026-07-22-2fa-console.md) ---
        // `login-form.tsx` never renders NextAuth's built-in credentials
        // form, so these never need a real `<input>`; they're declared
        // here purely to document the contract `authorize()` accepts.
        // The form completes the whole password -> 2FA-challenge/enroll
        // -> verify dance itself against the Rust API (`twofa-api.ts`)
        // and, once it holds a final token pair, calls
        // `signIn("credentials", { accessToken, refreshToken, user, ... })`.
        accessToken: { label: "Access Token", type: "text" },
        refreshToken: { label: "Refresh Token", type: "text" },
        // JSON-stringified `AppSessionUser` (`{ id, email }` — see
        // `twofa-api.ts`'s `Tokens.user`), e.g. `JSON.stringify(tokens.user)`.
        user: { label: "User", type: "text" },
        workspaceId: { label: "Workspace Id", type: "text" },
        role: { label: "Role", type: "text" },
        accessExpiresAt: { label: "Access Expires At", type: "text" },
        refreshExpiresAt: { label: "Refresh Expires At", type: "text" },
      },
      async authorize(credentials) {
        // --- Path 2: pre-obtained tokens (2FA flow) ---
        // By the time this branch runs, the login form has already
        // completed the full auth dance directly against the Rust
        // gateway over HTTPS (password -> 202 challenge/enroll -> code
        // verify -> final token pair; see `twofa-api.ts`). `authorize()`
        // here is a thin session wrapper: it just shapes the
        // already-issued tokens into the NextAuth `User` object.
        //
        // We deliberately do NOT verify the JWT client-side — there is
        // no signing secret available on this side to check it against,
        // and it isn't needed for security: every subsequent request
        // sends this access token to the Rust gateway, which
        // independently validates signature/expiry/revocation on every
        // call. A forged or stale token simply fails there, same as it
        // would for a token obtained via the password path.
        if (
          typeof credentials?.accessToken === "string" &&
          credentials.accessToken
        ) {
          const refreshToken =
            typeof credentials.refreshToken === "string"
              ? credentials.refreshToken
              : "";
          if (!refreshToken) return null;

          let parsedUser: { id?: string; email?: string } = {};
          if (typeof credentials.user === "string") {
            try {
              parsedUser = JSON.parse(credentials.user) as {
                id?: string;
                email?: string;
              };
            } catch {
              parsedUser = {};
            }
          }

          const email =
            parsedUser.email ??
            (typeof credentials.email === "string" ? credentials.email : "");
          if (!email) return null;
          const id = parsedUser.id ?? email;
          const workspaceId =
            typeof credentials.workspaceId === "string"
              ? credentials.workspaceId
              : "";
          const role = (
            typeof credentials.role === "string" ? credentials.role : "viewer"
          ) as AppRole;
          const accessExpiresAt = Number(credentials.accessExpiresAt ?? 0);
          const refreshExpiresAt = Number(credentials.refreshExpiresAt ?? 0);

          return {
            id,
            email,
            workspaceId,
            role,
            accessToken: credentials.accessToken,
            refreshToken,
            accessExpiresAt,
            refreshExpiresAt,
          };
        }

        // --- Path 1: email + password (existing, non-2FA users;
        // unchanged) ---
        const email = typeof credentials?.email === "string" ? credentials.email : "";
        const password =
          typeof credentials?.password === "string" ? credentials.password : "";
        if (!email || !password) return null;
        return authorizeWithBackend(email, password);
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      // First sign-in: copy backend-provided fields into the JWT.
      if (user) {
        const u = user as unknown as {
          id: string;
          email: string;
          workspaceId: string;
          role: AppRole;
          accessToken: string;
          refreshToken: string;
          accessExpiresAt: number;
          refreshExpiresAt: number;
        };
        return {
          ...token,
          sub: u.id,
          user: { id: u.id, email: u.email },
          workspaceId: u.workspaceId,
          role: u.role,
          accessToken: u.accessToken,
          refreshToken: u.refreshToken,
          accessExpiresAt: u.accessExpiresAt,
          refreshExpiresAt: u.refreshExpiresAt,
        };
      }

      // Subsequent requests: run silent refresh if the access token is stale.
      const appToken = token as unknown as AppJWT;
      if (!appToken.accessToken) return token;
      const refreshed = await refreshAccessTokenIfNeeded(appToken);
      return refreshed as unknown as typeof token;
    },
    async session({ session, token }) {
      const appToken = token as unknown as AppJWT;
      session.user = {
        ...session.user,
        id: appToken.user?.id ?? "",
        email: appToken.user?.email ?? session.user?.email ?? "",
      };
      session.workspaceId = appToken.workspaceId;
      session.role = appToken.role;
      session.accessToken = appToken.accessToken;
      session.refreshToken = appToken.refreshToken;
      session.accessExpiresAt = appToken.accessExpiresAt;
      session.refreshExpiresAt = appToken.refreshExpiresAt;
      session.error = appToken.error;
      return session;
    },
  },
};

export const { handlers, auth, signIn, signOut } = NextAuth(authConfig);
