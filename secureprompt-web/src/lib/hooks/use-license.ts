"use client";

/**
 * TanStack Query hooks for /v1/license.
 *
 * GET  /v1/license  → LicenseStatus
 * PUT  /v1/license  { token } → LicenseStatus
 * DELETE /v1/license → LicenseStatus
 *
 * WS6-4: on the generated client. `license-client.tsx` branches on
 * `err instanceof ApiError && err.status === 400` and on `error.status === 403`,
 * which is why every call here goes through `unwrap` rather than reading
 * `{ data, error }` directly — `unwrap` throws the same `ApiError` `apiFetch`
 * threw.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { makeApiClient, unwrap, type ApiError } from "@/lib/api-client";

import type { components } from "@/types/api.gen";

export type LicenseStatus = components["schemas"]["LicenseStatus"];
export type LicenseSource = LicenseStatus["source"];
/**
 * Not generated: the gateway serialises `license::Status` with `Display`, so
 * the OpenAPI document types `status` as a bare string rather than an enum.
 * Kept as a named union for the console's switch, and deliberately NOT
 * asserted onto `LicenseStatus["status"]` — that would be inventing a contract
 * the server does not publish. WS6-4-FU3.
 */
export type LicenseStatusValue = "Valid" | "Grace" | "Unlicensed" | "Revoked";

export const LICENSE_QUERY_KEY = ["license"] as const;

export function useLicense() {
  return useQuery<LicenseStatus, ApiError>({
    queryKey: LICENSE_QUERY_KEY,
    queryFn: () => unwrap(makeApiClient().GET("/v1/license")),
  });
}

export function useActivateLicense() {
  const qc = useQueryClient();
  return useMutation<LicenseStatus, ApiError, { token: string }>({
    mutationFn: (body) => unwrap(makeApiClient().PUT("/v1/license", { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: LICENSE_QUERY_KEY }),
  });
}

export function useRemoveLicense() {
  const qc = useQueryClient();
  return useMutation<LicenseStatus, ApiError, void>({
    mutationFn: () => unwrap(makeApiClient().DELETE("/v1/license")),
    onSuccess: () => qc.invalidateQueries({ queryKey: LICENSE_QUERY_KEY }),
  });
}
