/**
 * Authenticated fetch wrapper for the Rust gateway.
 *
 * - Prepends NEXT_PUBLIC_API_URL.
 * - JSON-serializes opts.body.
 * - Attaches `Authorization: Bearer <accessToken>` — branches client vs.
 *   server: on the server calls `auth()` from `@/lib/auth`; on the client
 *   calls `getSession()` from `next-auth/react`.
 * - On 401: if `signOutOn401 !== false` and running in the browser,
 *   signOut({ callbackUrl: "/login?reason=expired" }).
 * - On 402: throw ApiError{ code: "budget_exceeded" } (Plan 05 renders a toast).
 * - On other non-2xx: parse `ApiErrorEnvelope` and throw a typed ApiError.
 *
 * Plans 03/04 typically use the openapi-fetch client (src/lib/api-client.ts)
 * for typed paths; this helper is a lower-level escape hatch.
 */
import type { ApiErrorEnvelope } from "@/types/api";

const DEFAULT_API_URL = "http://localhost:8080";

export interface ApiFetchOptions extends Omit<RequestInit, "body"> {
  /** JSON-serialized automatically. */
  body?: unknown;
  /** Default true — set false to suppress automatic signOut on 401. */
  signOutOn401?: boolean;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;

  constructor(
    message: string,
    opts: { status: number; code: string; details?: unknown },
  ) {
    super(message);
    this.name = "ApiError";
    this.status = opts.status;
    this.code = opts.code;
    this.details = opts.details;
  }
}

/** Thrown when the request never reached the server (network down, DNS failure, timeout). */
export class NetworkError extends Error {
  readonly isNetworkError = true as const;

  constructor(message: string) {
    super(message);
    this.name = "NetworkError";
  }
}

function apiBaseUrl(): string {
  const url = process.env.NEXT_PUBLIC_API_URL ?? DEFAULT_API_URL;
  return url.replace(/\/+$/, "");
}

/**
 * Returns the bearer access token for the current request — server or
 * client — or undefined if no session is active. Exported so api-client.ts
 * can reuse the same resolution logic.
 */
export async function getBearerForRequest(): Promise<string | undefined> {
  if (typeof window === "undefined") {
    // Server: use auth() which is RSC-safe.
    const { auth } = await import("@/lib/auth");
    const session = await auth();
    return session?.accessToken;
  }
  // Client.
  const { getSession } = await import("next-auth/react");
  const session = await getSession();
  return (session as unknown as { accessToken?: string } | null)?.accessToken;
}

async function parseError(
  res: Response,
): Promise<{ code: string; message: string; details?: unknown }> {
  const fallback = {
    code: `http_${res.status}`,
    message: res.statusText || `HTTP ${res.status}`,
  };
  const text = await res.text().catch(() => "");
  if (!text) return fallback;
  try {
    const parsed = JSON.parse(text) as { error?: Partial<ApiErrorEnvelope> };
    return {
      code: parsed.error?.code ?? fallback.code,
      message: parsed.error?.message ?? fallback.message,
    };
  } catch {
    return { ...fallback, details: text };
  }
}

async function signOutOn401IfClient(): Promise<void> {
  if (typeof window === "undefined") return;
  try {
    const { signOut } = await import("next-auth/react");
    await signOut({ callbackUrl: "/login?reason=expired" });
  } catch {
    // best-effort; swallow so callers still see the ApiError.
  }
}

export async function apiFetch<T = unknown>(
  path: string,
  opts: ApiFetchOptions = {},
): Promise<T> {
  const { body, headers, signOutOn401 = true, ...rest } = opts;
  const token = await getBearerForRequest();
  const init: RequestInit = {
    ...rest,
    headers: {
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(headers ?? {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  };

  const url = path.startsWith("http") ? path : `${apiBaseUrl()}${path}`;
  let res: Response;
  try {
    res = await fetch(url, init);
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") {
      throw new NetworkError("Request timed out or was aborted");
    }
    if (e instanceof TypeError) {
      throw new NetworkError(e.message || "Network request failed");
    }
    throw e;
  }

  if (res.status === 401 && signOutOn401) {
    await signOutOn401IfClient();
  }

  if (res.status === 402) {
    const err = await parseError(res);
    // Notify the BudgetBanner component so it can render a toast/banner.
    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("sp:budget-exceeded", { detail: err }));
    }
    throw new ApiError(err.message, {
      status: 402,
      code: err.code || "budget_exceeded",
      details: err.details,
    });
  }

  if (!res.ok) {
    const err = await parseError(res);
    throw new ApiError(err.message, {
      status: res.status,
      code: err.code,
      details: err.details,
    });
  }

  if (res.status === 204) {
    return undefined as T;
  }

  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return (await res.json()) as T;
  }
  return (await res.text()) as unknown as T;
}
