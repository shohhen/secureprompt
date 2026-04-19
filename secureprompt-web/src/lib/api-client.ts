/**
 * Typed openapi-fetch client for the Rust gateway.
 *
 * Wraps `fetch` so that every call carries the current bearer token and
 * triggers `signOut()` on 401 (client only) — same contract as `apiFetch`
 * but with end-to-end type safety from the OpenAPI paths.
 *
 * Usage (in a Client Component or RSC):
 *   const client = makeApiClient();
 *   const { data, error } = await client.POST("/v1/auth/token", {
 *     body: { email, password },
 *   });
 */
import createClient from "openapi-fetch";
import type { paths } from "@/types/api.gen";
import { getBearerForRequest } from "./api-fetch";

const DEFAULT_API_URL = "http://localhost:8080";

function apiBaseUrl(): string {
  const url = process.env.NEXT_PUBLIC_API_URL ?? DEFAULT_API_URL;
  return url.replace(/\/+$/, "");
}

export function makeApiClient() {
  return createClient<paths>({
    baseUrl: apiBaseUrl(),
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      const token = await getBearerForRequest();
      const next: RequestInit = {
        ...init,
        headers: {
          ...(init?.headers ?? {}),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      };
      const res = await fetch(input, next);
      if (res.status === 401 && typeof window !== "undefined") {
        try {
          const { signOut } = await import("next-auth/react");
          await signOut({ callbackUrl: "/login?reason=expired" });
        } catch {
          // best-effort
        }
      }
      return res;
    },
  });
}
