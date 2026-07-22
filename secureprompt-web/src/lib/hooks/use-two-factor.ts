"use client";

/**
 * TanStack Query mutations for the Settings -> Security 2FA panel (Task 7 of
 * docs/superpowers/plans/2026-07-22-2fa-console.md).
 *
 * These wrap the `twofa-api.ts` helpers -- the same module the login flow's
 * challenge/enrollment screens use (Tasks 2/5/6) -- but run for an ALREADY
 * LOGGED-IN user, so the bearer is the session's access token rather than a
 * short-lived `challenge_token`/`enrollment_token`. Mirrors the mutation
 * shape of `use-secure-mode.ts` (`useMutation` wrapping a typed call, no
 * query caching needed since these are one-shot actions, not cached reads).
 *
 * Bearer resolution: read the same way `api-fetch.ts`'s
 * `getBearerForRequest()` resolves it on the client (`next-auth/react`'s
 * `getSession()`), rather than re-deriving the token some other way.
 * `getBearerForRequest` itself isn't reused directly because it also
 * branches for the server/RSC case via `auth()` -- these hooks are
 * client-only (`"use client"` mutations bound to a settings form), so only
 * the client branch is needed.
 *
 * No 2FA "status" endpoint exists on the backend (see twofa-api.ts's
 * `TwoFaAlreadyEnabledError` doc comment) -- `useEnroll2fa()` doubles as the
 * status probe `security-client.tsx` uses (a 200 means "not enrolled yet"
 * and returns the QR data; a thrown `TwoFaAlreadyEnabledError` means
 * "already enrolled"). These hooks don't add a status endpoint themselves,
 * they just expose the existing enroll/verify/disable calls as mutations.
 */
import { useMutation } from "@tanstack/react-query";
import { getSession } from "next-auth/react";
import {
  enroll,
  verify2fa,
  disable2fa,
  type EnrollResult,
  type Tokens,
} from "@/lib/twofa-api";

/** Resolves the current session's access token on the client, or throws if
 *  there isn't one (shouldn't happen under `(dashboard)/layout.tsx`'s
 *  server-side auth redirect, but mutations need a concrete error to
 *  reject with rather than silently calling the API with no bearer). */
async function requireAccessToken(): Promise<string> {
  const session = await getSession();
  const token = (session as unknown as { accessToken?: string } | null)
    ?.accessToken;
  if (!token) throw new Error("Not signed in.");
  return token;
}

/**
 * Begin (or re-fetch) 2FA enrollment for the CURRENT logged-in account
 * (`POST /v1/auth/2fa/enroll` with the session access token as bearer).
 * Resolves to the QR/secret/backup-codes payload on success, `null` on a
 * generic failure, or rejects with `TwoFaAlreadyEnabledError` if the
 * account already has confirmed 2FA -- `security-client.tsx` uses that
 * three-way outcome as its status probe.
 */
export function useEnroll2fa() {
  return useMutation<EnrollResult | null, Error, void>({
    mutationFn: async () => enroll(await requireAccessToken()),
  });
}

/**
 * Confirm enrollment with a TOTP code (`POST /v1/auth/2fa/verify`).
 * Resolves to the reissued `Tokens` on success (ignored by the Settings
 * page -- the user already has a session) or `null` on an invalid code.
 */
export function useVerify2fa() {
  return useMutation<Tokens | null, Error, string>({
    mutationFn: async (code) => verify2fa(await requireAccessToken(), code),
  });
}

/**
 * Disable 2FA on the current account (`POST /v1/auth/2fa/disable`).
 * Requires a current TOTP or backup code; resolves `true` on success.
 */
export function useDisable2fa() {
  return useMutation<boolean, Error, string>({
    mutationFn: async (code) => disable2fa(await requireAccessToken(), code),
  });
}
