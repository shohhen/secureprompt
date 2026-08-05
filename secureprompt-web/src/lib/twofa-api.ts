/**
 * Typed 2FA API helpers (Task 2 of docs/superpowers/plans/2026-07-22-2fa-console.md).
 *
 * WS6-4 — this module used to talk to `POST /v1/auth/token` and
 * `POST /v1/auth/2fa/*` with plain `fetch`, and said why in this comment:
 * "the 202 challenge/enroll response shapes for /v1/auth/token aren't
 * represented in the generated OpenAPI types". They are now
 * (`TwoFactorPending`, plus the four `/v1/auth/2fa/*` paths that were served
 * and undocumented), so the reason is gone and this file is on the generated
 * client like every other data hook.
 *
 * Two things it deliberately does NOT take from `api-client.ts`:
 *
 *   * `unwrap()`. The public contract here is `Tokens | null` and
 *     `LoginResult`, with two typed throws (`TwoFaLockedError` on 429,
 *     `TwoFaAlreadyEnabledError` on 409) that the challenge and settings
 *     screens branch on. Throwing `ApiError` instead would be a behaviour
 *     change for every caller, so the status mapping below is unchanged —
 *     only the transport moved.
 *   * the session bearer and the 401 signOut. These run DURING login, when
 *     there is no session: the bearer is a short-lived `challenge_token` /
 *     `enrollment_token`, and a signOut redirect on a wrong TOTP code would
 *     bounce the user out of the flow they are in the middle of. Hence
 *     `makeApiClient({ bearer, signOutOn401: false })`.
 *
 * Base URL resolution comes from `api-client.ts` (`NEXT_PUBLIC_API_URL`,
 * falling back to `http://localhost:8080`) rather than `auth.ts`'s
 * server-only `API_URL` — these helpers are called from client components
 * (login form, challenge/enroll screens, settings page).
 *
 * Pure module: no React, no next-auth imports. Never logs tokens/secrets.
 */
import { makeApiClient } from "@/lib/api-client";
import type { components } from "@/types/api.gen";
import type { AppRole, AppSessionUser } from "@/types/next-auth";

type BackendTokenResponse = components["schemas"]["TokenResponse"];
type TwoFactorPending = components["schemas"]["TwoFactorPending"];
type BackendEnrollResponse =
  components["schemas"]["TwoFactorEnrollResponse"];

/** camelCase mirror of the backend's `TokenResponse`. */
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
    user: body.user as AppSessionUser | undefined,
    workspaceId: body.workspace_id,
    role: body.role as AppRole | undefined,
    accessExpiresAt: body.access_expires_at,
    refreshExpiresAt: body.refresh_expires_at,
  };
}

/**
 * A client with no session bearer and no signOut-on-401 — see the module
 * doc. `bearer` is a purpose token, or absent entirely for `loginStep1`.
 */
function authClient(bearer?: string) {
  // `bearer ?? null` — never fall back to the session. `loginStep1` passes
  // nothing and must send no Authorization header at all; resolving one would
  // add a `getSession()` round-trip the raw-fetch version never made, and
  // `tests/unit/refresh-token-transits-the-browser-at-login.test.ts` counts
  // the calls.
  return makeApiClient({ bearer: bearer ?? null, signOutOn401: false });
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
  let result;
  try {
    result = await authClient().POST("/v1/auth/token", {
      body: { email, password },
    });
  } catch {
    // makeApiClient turns a transport failure into NetworkError; this
    // module's contract is `kind: "error"`, unchanged from the raw-fetch
    // version's bare `catch`.
    return { kind: "error" };
  }

  const { data, response } = result;

  if (response.status === 200) {
    const body = data as BackendTokenResponse | undefined;
    if (!body?.access_token || !body.refresh_token) return { kind: "error" };
    return { kind: "tokens", tokens: mapTokens(body) };
  }

  if (response.status === 202) {
    const body = data as TwoFactorPending | undefined;
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
  let result;
  try {
    result = await authClient(challengeToken).POST("/v1/auth/2fa/challenge", {
      body: { code },
    });
  } catch {
    return null;
  }

  if (result.response.status === 429) {
    throw new TwoFaLockedError();
  }
  if (result.response.status !== 200) return null;

  const body = result.data as BackendTokenResponse | undefined;
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
  let result;
  try {
    result = await authClient(bearer).POST("/v1/auth/2fa/enroll", {});
  } catch {
    return null;
  }

  if (result.response.status === 409) {
    throw new TwoFaAlreadyEnabledError();
  }
  if (result.response.status !== 200) return null;

  const body = result.data as BackendEnrollResponse | undefined;
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
  let result;
  try {
    result = await authClient(bearer).POST("/v1/auth/2fa/verify", {
      body: { code },
    });
  } catch {
    return null;
  }

  if (result.response.status !== 200) return null;

  const body = result.data as BackendTokenResponse | undefined;
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
  let result;
  try {
    result = await authClient(accessToken).POST("/v1/auth/2fa/disable", {
      body: { code },
    });
  } catch {
    return false;
  }

  return result.response.status === 200;
}
