/**
 * Typed openapi-fetch client for the Rust gateway.
 *
 * Wraps `fetch` so that every call carries the current bearer token and
 * triggers `signOut()` on 401 (client only) — same contract as `apiFetch`
 * but with end-to-end type safety from the OpenAPI paths.
 *
 * Usage (in a Client Component or RSC):
 *   const client = makeApiClient();
 *   const tokens = await unwrap(
 *     await client.POST("/v1/auth/token", { body: { email, password } }),
 *   );
 *
 * WS6-4 — `unwrap()` exists because `openapi-fetch` never throws. It returns
 * `{ data, error, response }`, so a hook that forgets to check `error` hands
 * TanStack Query `undefined` and a "successful" query. Every data hook in
 * `src/lib/hooks/` now goes through `unwrap`, and its error contract is
 * deliberately IDENTICAL to `apiFetch`'s, because call sites already branch
 * on that contract:
 *   * `app/(dashboard)/settings/license/license-client.tsx` —
 *     `err instanceof ApiError && err.status === 400`
 *   * `app/(dashboard)/error.tsx` — `error instanceof ApiError`
 * and two components listen for the 402 event
 * (`components/providers.tsx`, `components/layout/topbar.tsx`).
 * `tests/unit/generated-client-migration.test.ts` pins all seven behaviours.
 */
import createClient from "openapi-fetch";
import type { paths } from "@/types/api.gen";
import { ApiError, NetworkError, getBearerForRequest } from "./api-fetch";
import type { ApiErrorEnvelope } from "@/types/api";

/**
 * Re-exported so a data hook has exactly ONE transport import. `unwrap`
 * throws these, and `tests/unit/generated-client-migration.test.ts` forbids
 * `@/lib/api-fetch` inside `src/lib/hooks/` outright — a hook that reaches
 * for `apiFetch` and a hook that reaches for its error type look identical
 * to a grep, and only one of them is a regression.
 */
export { ApiError, NetworkError };

const DEFAULT_API_URL = "http://localhost:8080";

function apiBaseUrl(): string {
  const url = process.env.NEXT_PUBLIC_API_URL ?? DEFAULT_API_URL;
  return url.replace(/\/+$/, "");
}

export interface ApiClientOptions {
  /**
   * Bearer to send instead of the session's access token.
   *
   * Three states, and the third is load-bearing:
   *   * omitted  — resolve the session access token (`getBearerForRequest`);
   *   * a string — send that instead, and do not touch the session. The 2FA
   *     login flow needs this: `challenge_token` and `enrollment_token` are
   *     short-lived purpose tokens handed back by the 202 on
   *     `POST /v1/auth/token`;
   *   * `null`   — send NO Authorization header and do not look one up.
   *     `loginStep1` is the caller: there is no session yet, and resolving
   *     one would fire an extra `getSession()` round-trip to
   *     `/api/auth/session` on every login attempt — a request the raw-fetch
   *     version never made.
   */
  bearer?: string | null;
  /** Default true — set false to suppress the automatic signOut on 401. */
  signOutOn401?: boolean;
}

export function makeApiClient(opts: ApiClientOptions = {}) {
  const { bearer, signOutOn401 = true } = opts;
  return createClient<paths>({
    baseUrl: apiBaseUrl(),
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      const token =
        bearer === null ? undefined : (bearer ?? (await getBearerForRequest()));

      // MERGE, do not replace.
      //
      // openapi-fetch calls this hook as `fetch(request)` — a fully built
      // `Request` carrying `Content-Type: application/json` for any verb with
      // a body — and passes no `init`. Handing `fetch(request, { headers })`
      // back to the platform REPLACES the request's header list wholesale
      // (WHATWG fetch, Request constructor step "if init.headers exists, empty
      // headers then fill"), so the object-literal spread this used to do
      // silently dropped Content-Type and every POST/PUT/PATCH would have hit
      // axum's `Json<T>` extractor as 415 Unsupported Media Type.
      //
      // It never showed because the only caller before WS6-4 was
      // `use-analytics`, which is four GETs. Measured with a probe:
      //   before  EFFECTIVE_CT null
      //   after   EFFECTIVE_CT application/json
      // and pinned by `generated-client-migration.test.ts`
      // ("preserves the Content-Type openapi-fetch set").
      const headers = new Headers(
        input instanceof Request ? input.headers : undefined,
      );
      new Headers(init?.headers ?? {}).forEach((value, key) => {
        headers.set(key, value);
      });
      if (token) headers.set("Authorization", `Bearer ${token}`);
      const next: RequestInit = { ...init, headers };
      let res: Response;
      try {
        res = await fetch(input, next);
      } catch (e) {
        // Same classification as apiFetch: "we never reached the server" is a
        // different thing from "the server said something wrong", and the
        // error boundary renders them differently.
        if (e instanceof DOMException && e.name === "AbortError") {
          throw new NetworkError("Request timed out or was aborted");
        }
        if (e instanceof TypeError) {
          throw new NetworkError(e.message || "Network request failed");
        }
        throw e;
      }
      if (res.status === 401 && signOutOn401 && typeof window !== "undefined") {
        try {
          const { signOut } = await import("next-auth/react");
          await signOut({ callbackUrl: "/login?reason=expired" });
        } catch {
          // best-effort
        }
      }
      if (res.status === 402 && typeof window !== "undefined") {
        // BudgetBanner + topbar listen for this. `res.clone()` because
        // openapi-fetch still has to read the body for `error`.
        const detail = await errorDetail(res.clone());
        window.dispatchEvent(new CustomEvent("sp:budget-exceeded", { detail }));
      }
      return res;
    },
  });
}

/** Shape openapi-fetch returns from every verb method. */
interface FetchResult<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

async function errorDetail(
  res: Response,
): Promise<{ code: string; message: string; details?: unknown }> {
  const fallback = {
    code: `http_${res.status}`,
    message: res.statusText || `HTTP ${res.status}`,
  };
  const text = await res.text().catch(() => "");
  if (!text) return fallback;
  try {
    const parsed = JSON.parse(text) as Partial<ApiErrorEnvelope>;
    return {
      code: parsed.error?.code ?? fallback.code,
      message: parsed.error?.message ?? fallback.message,
    };
  } catch {
    return { ...fallback, details: text };
  }
}

function apiErrorFrom(error: unknown, res: Response): ApiError {
  const fallbackCode = `http_${res.status}`;
  const envelope =
    error && typeof error === "object"
      ? (error as Partial<ApiErrorEnvelope>)
      : {};
  const code = envelope.error?.code ?? fallbackCode;
  const message =
    envelope.error?.message ||
    res.statusText ||
    `HTTP ${res.status}`;
  return new ApiError(message, {
    status: res.status,
    code,
    // A non-JSON body arrives as a string in `error`; keep it for the error
    // boundary rather than discarding it.
    details: typeof error === "string" ? error : undefined,
  });
}

/**
 * Turn an openapi-fetch result into the value, or throw the same `ApiError`
 * `apiFetch` would have thrown.
 *
 * Takes the promise as well as the resolved value so a hook reads
 * `unwrap(client.GET(...))` rather than `unwrap(await client.GET(...))` —
 * one fewer place to forget an `await`, which openapi-fetch would otherwise
 * silently accept as a truthy object with no `data`.
 *
 * `undefined` on 204 mirrors `apiFetch`'s early return: DELETE routes are
 * typed `void` and openapi-fetch leaves `data` unset for an empty body.
 */
export async function unwrap<T>(
  result: FetchResult<T> | Promise<FetchResult<T>>,
): Promise<T> {
  const { data, error, response } = await result;
  if (response.ok) {
    return data as T;
  }
  throw apiErrorFrom(error, response);
}
