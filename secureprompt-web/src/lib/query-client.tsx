"use client";

/**
 * TanStack Query v5 client factory + Providers barrel.
 *
 * With Next.js App Router, a NEW QueryClient must be created per request on
 * the server (to prevent request bleed) and ONCE per browser tab on the
 * client. The `getQueryClient()` helper encodes this pattern.
 *
 * Consumed by `src/components/providers.tsx`.
 */
import { QueryClient } from "@tanstack/react-query";

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 60_000,
        refetchOnWindowFocus: false,
        retry: 1,
      },
    },
  });
}

let browserQueryClient: QueryClient | undefined;

export function getQueryClient(): QueryClient {
  if (typeof window === "undefined") {
    // Server: always a fresh client (request-scoped).
    return makeQueryClient();
  }
  // Browser: singleton.
  if (!browserQueryClient) {
    browserQueryClient = makeQueryClient();
  }
  return browserQueryClient;
}
