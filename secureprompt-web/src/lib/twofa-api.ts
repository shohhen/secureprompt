/**
 * Typed 2FA API helpers (Task 2 of docs/superpowers/plans/2026-07-22-2fa-console.md).
 *
 * Talks directly to the Rust gateway's `POST /v1/auth/token` and
 * `POST /v1/auth/2fa/*` endpoints with plain `fetch` — NOT the openapi-fetch
 * client in `api-client.ts` — because the 202 challenge/enroll response
 * shapes for `/v1/auth/token` aren't represented in the generated OpenAPI
 * types (`src/types/api.gen.ts` only models the 200 `TokenResponse` case;
 * see `secureprompt-api/src/http/routes/dashboard/auth.rs` for the 202
 * `{twofa_required, challenge_token}` / `{enroll_required, enrollment_token}`
 * bodies).
 *
 * Base URL resolution matches `api-client.ts` / `api-fetch.ts`
 * (`NEXT_PUBLIC_API_URL`, falling back to `http://localhost:8080`) rather
 * than `auth.ts`'s server-only `API_URL` — these helpers are called from
 * client components (login form, challenge/enroll screens, settings page).
 *
 * Pure module: no React, no next-auth imports. Never logs tokens/secrets.
 */
import type { AppRole, AppSessionUser } from "@/types/next-auth";

const DEFAULT_API_URL = "http://localhost:8080";

function apiBaseUrl(): string {
  const url = process.env.NEXT_PUBLIC_API_URL ?? DEFAULT_API_URL;
  return url.replace(/\/+$/, "");
}

/** Backend `TokenResponse` shape (snake_case) — success body for
 *  `/v1/auth/token`, `/v1/auth/2fa/challenge`, and `/v1/auth/2fa/verify`. */
interface BackendTokenResponse {
  access_token: string;
  refresh_token: string;
  /** Unix seconds */
  access_expires_at: number;
  /** Unix seconds */
  refresh_expires_at: number;
  user?: AppSessionUser;
  workspace_id?: string;
  role?: AppRole;
}

/** camelCase mirror of `BackendTokenResponse`. */
export interface Tokens {
  accessToken: string;
  refreshToken: string;
  user?: AppSessionUser;
  workspaceId?: string;
  role?: AppRole;
  /** Unix seconds */
  accessExpiresAt: number;
  /** Unix seconds */
  refreshExpiresAt: number;
}

export type LoginResult =
  | { kind: "tokens"; tokens: Tokens }
  | { kind: "challenge"; challengeToken: string }
  | { kind: "enroll"; enrollmentToken: string }
  | { kind: "error" };

interface BackendEnrollResponse {
  provisioning_uri: string;
  secret_b32: string;
  backup_codes: string[];
}

export interface EnrollResult {
  provisioningUri: string;
  secretB32: string;
  backupCodes: string[];
}

/**
 * Thrown by `challenge()` on HTTP 429.
 *
 * `POST /v1/auth/2fa/challenge` is rate-limited both per-account (lockout
 * after repeated bad codes) and per-IP (`secureprompt-api/src/http/routes/
 * dashboard/twofactor.rs`); both surface as 429. The plan's challenge
 * screen (Task 5) needs to show a distinct "locked, try again later"
 * message instead of the generic invalid-code error, so `challenge()`
 * throws this typed error on 429 rather than folding it into the
 * `Tokens | null` result (matching the `ApiError`/`NetworkError` typed-throw
 * convention already used in `api-fetch.ts`). Callers: `if (e instanceof
 * TwoFaLockedError) { ... }`.
 */
export class TwoFaLockedError extends Error {
  constructor(message = "Too many attempts. Try again later.") {
    super(message);
    this.name = "TwoFaLockedError";
  }
}

/**
 * Thrown by `enroll()` on HTTP 409 (`secureprompt-api/src/http/routes/
 * dashboard/twofactor.rs` `enroll()`: "2FA is already enabled; disable it
 * first" when `totp_confirmed_at` is already set).
 *
 * There is no dedicated "is 2FA enabled" GET endpoint (Task 7 of
 * docs/superpowers/plans/2026-07-22-2fa-console.md). `settings/security/
 * page.tsx` infers status pragmatically by calling `enroll()` and reading
 * the outcome: a 200 means "not enrolled yet" (and doubles as fetching the
 * QR data), a 409 means "already enrolled" -- surfaced via this typed error
 * so the caller can tell it apart from a genuine failure (network/500,
 * still `null`) instead of collapsing both into the same falsy result.
 * Same pattern as `TwoFaLockedError` above for `challenge()`'s 429.
 * Existing callers that don't care about the distinction (the login flow's
 * forced-enrollment screen, `two-factor-enroll.tsx`) already funnel any
 * thrown error into a generic "something went wrong" state, so this is a
 * behavior-preserving change for them.
 */
export class TwoFaAlreadyEnabledError extends Error {
  constructor(message = "Two-factor authentication is already enabled.") {
    super(message);
    this.name = "TwoFaAlreadyEnabledError";
  }
}

function mapTokens(body: BackendTokenResponse): Tokens {
  return {
    accessToken: body.access_token,
    refreshToken: body.refresh_token,
    user: body.user,
    workspaceId: body.workspace_id,
    role: body.role,
    accessExpiresAt: body.access_expires_at,
    refreshExpiresAt: body.refresh_expires_at,
  };
}

async function safeJson<T>(res: Response): Promise<T | null> {
  try {
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

/**
 * Step 1 of login: `POST /v1/auth/token`.
 * - 200 -> login complete, tokens issued (`kind: "tokens"`).
 * - 202 with `challenge_token` -> account has 2FA enabled, needs a code
 *   (`kind: "challenge"`).
 * - 202 with `enrollment_token` -> 2FA is mandatory for this account and it
 *   hasn't enrolled yet (`kind: "enroll"`).
 * - anything else (401 invalid credentials, network failure, ...) ->
 *   `kind: "error"`.
 */
export async function loginStep1(
  email: string,
  password: string,
): Promise<LoginResult> {
  let res: Response;
  try {
    res = await fetch(`${apiBaseUrl()}/v1/auth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
  } catch {
    return { kind: "error" };
  }

  if (res.status === 200) {
    const body = await safeJson<BackendTokenResponse>(res);
    if (!body?.access_token || !body.refresh_token) return { kind: "error" };
    return { kind: "tokens", tokens: mapTokens(body) };
  }

  if (res.status === 202) {
    const body = await safeJson<{
      challenge_token?: string;
      enrollment_token?: string;
    }>(res);
    if (body?.challenge_token) {
      return { kind: "challenge", challengeToken: body.challenge_token };
    }
    if (body?.enrollment_token) {
      return { kind: "enroll", enrollmentToken: body.enrollment_token };
    }
  }

  return { kind: "error" };
}

/**
 * Submit a TOTP or backup code against a `2fa_challenge` bearer token
 * (`POST /v1/auth/2fa/challenge`).
 *
 * Returns `Tokens` on success (200), `null` on an invalid code or any
 * other failure. Throws `TwoFaLockedError` on 429 — see that class's
 * doc comment.
 */
export async function challenge(
  challengeToken: string,
  code: string,
): Promise<Tokens | null> {
  let res: Response;
  try {
    res = await fetch(`${apiBaseUrl()}/v1/auth/2fa/challenge`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${challengeToken}`,
      },
      body: JSON.stringify({ code }),
    });
  } catch {
    return null;
  }

  if (res.status === 429) {
    throw new TwoFaLockedError();
  }
  if (res.status !== 200) return null;

  const body = await safeJson<BackendTokenResponse>(res);
  if (!body?.access_token) return null;
  return mapTokens(body);
}

/**
 * Begin 2FA enrollment (`POST /v1/auth/2fa/enroll`, no request body).
 * `bearer` may be an `enrollment_token` (mandatory-enrollment flow from
 * `loginStep1`) or a normal access token (Settings -> Security opt-in).
 * Returns `null` on a non-200/409 failure (network, 500, ...). Throws
 * `TwoFaAlreadyEnabledError` on 409 -- see that class's doc comment.
 */
export async function enroll(bearer: string): Promise<EnrollResult | null> {
  let res: Response;
  try {
    res = await fetch(`${apiBaseUrl()}/v1/auth/2fa/enroll`, {
      method: "POST",
      headers: { Authorization: `Bearer ${bearer}` },
    });
  } catch {
    return null;
  }

  if (res.status === 409) {
    throw new TwoFaAlreadyEnabledError();
  }
  if (res.status !== 200) return null;

  const body = await safeJson<BackendEnrollResponse>(res);
  if (!body?.provisioning_uri || !body.secret_b32 || !body.backup_codes) {
    return null;
  }

  return {
    provisioningUri: body.provisioning_uri,
    secretB32: body.secret_b32,
    backupCodes: body.backup_codes,
  };
}

/**
 * Confirm enrollment with a TOTP code (`POST /v1/auth/2fa/verify`). `bearer`
 * is the same enrollment_token or access token passed to `enroll()`.
 * Returns `Tokens` on success (200), `null` on any other status.
 */
export async function verify2fa(
  bearer: string,
  code: string,
): Promise<Tokens | null> {
  let res: Response;
  try {
    res = await fetch(`${apiBaseUrl()}/v1/auth/2fa/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${bearer}`,
      },
      body: JSON.stringify({ code }),
    });
  } catch {
    return null;
  }

  if (res.status !== 200) return null;

  const body = await safeJson<BackendTokenResponse>(res);
  if (!body?.access_token) return null;
  return mapTokens(body);
}

/**
 * Disable 2FA on the current account (`POST /v1/auth/2fa/disable`,
 * Settings -> Security). Requires a real access token (not an
 * enrollment/challenge token) plus a current TOTP or backup code.
 * Returns `true` on success (200), `false` otherwise.
 */
export async function disable2fa(
  accessToken: string,
  code: string,
): Promise<boolean> {
  let res: Response;
  try {
    res = await fetch(`${apiBaseUrl()}/v1/auth/2fa/disable`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({ code }),
    });
  } catch {
    return false;
  }

  return res.status === 200;
}
