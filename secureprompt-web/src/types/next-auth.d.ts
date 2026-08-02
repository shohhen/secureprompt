/**
 * Module augmentation for next-auth v5.
 * Keeps the Session / User / JWT shapes in lockstep with the Rust API's
 * TokenResponse contract (see secureprompt-schemas/openapi/v1/openapi.yaml).
 */
import type { DefaultSession, DefaultUser } from "next-auth";
import type { DefaultJWT } from "next-auth/jwt";

export type AppRole =
  | "owner"
  | "admin"
  | "developer"
  | "employee"
  | "viewer";

export interface AppSessionUser {
  id: string;
  email: string;
}

export interface AppSessionShape {
  user: AppSessionUser;
  workspaceId: string;
  role: AppRole;
  accessToken: string;
  // NO refreshToken here (WS1-9): this shape is the CLIENT-VISIBLE session
  // (`useSession()` / `getSession()` / `auth()`'s return value) — anything
  // on it is readable by client-side JavaScript for the whole life of the
  // session. Keeping the long-lived refresh token off it is what stops an
  // XSS payload, a compromised dependency or a browser extension from
  // minting access tokens indefinitely. After sign-in it lives only in the
  // encrypted JWT cookie (see the `User`/`JWT` augmentations below and
  // `buildClientSessionFields` in `src/lib/auth-refresh.ts`).
  //
  // CORRECTED (MR1 review I9). This comment used to say the refresh token
  // "must never leave the server", and that is not what this codebase does.
  // `src/lib/twofa-api.ts::loginStep1` is a browser `fetch` that reads
  // `body.refresh_token`, and `src/app/(auth)/login/login-form.tsx` — a
  // "use client" component — passes it to `signIn("credentials", …)`. The
  // token is therefore materialised in page JavaScript ONCE PER SIGN-IN and
  // POSTed through NextAuth's credentials endpoint on its way into the
  // cookie. It does not "live only" in the cookie; it ENDS UP there.
  //
  // The true property, and the one worth having: the refresh token is not
  // exposed for the LIFETIME of the session, only during the sign-in turn.
  // An XSS present during that one turn still captures it. Closing that
  // needs the `/v1/auth/token` exchange moved into a server action or route
  // handler so the token never reaches client JS; that is a real change to
  // the 2FA challenge/enroll flows and is not made here. Pinned by
  // `tests/unit/refresh-token-transits-the-browser-at-login.test.ts`, which
  // reddens if the exchange ever moves — at which point this comment can be
  // strengthened rather than being quietly wrong again.
  accessExpiresAt: number; // unix seconds
  refreshExpiresAt: number; // unix seconds
  error?: "RefreshAccessTokenError";
}

declare module "next-auth" {
  interface Session extends AppSessionShape {
    // Keep default fields (expires) while overriding user with our narrow shape.
    user: AppSessionUser & DefaultSession["user"];
  }

  interface User extends DefaultUser {
    id: string;
    email: string;
    workspaceId: string;
    role: AppRole;
    accessToken: string;
    refreshToken: string;
    accessExpiresAt: number;
    refreshExpiresAt: number;
  }
}

declare module "next-auth/jwt" {
  interface JWT extends DefaultJWT {
    user: AppSessionUser;
    workspaceId: string;
    role: AppRole;
    accessToken: string;
    refreshToken: string;
    accessExpiresAt: number;
    refreshExpiresAt: number;
    error?: "RefreshAccessTokenError";
  }
}
