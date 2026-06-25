"use client";

/**
 * TanStack Query hooks for /v1/license.
 *
 * GET  /v1/license  → LicenseStatus
 * PUT  /v1/license  { token } → LicenseStatus
 * DELETE /v1/license → LicenseStatus
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";

export type LicenseStatusValue = "Valid" | "Grace" | "Unlicensed" | "Revoked";
export type LicenseSource = "db" | "env" | "none";

export interface LicenseStatus {
  customer_name: string | null;
  lic_id: string | null;
  expires_at: string | null;
  features: string[];
  status: LicenseStatusValue;
  source: LicenseSource;
}

export const LICENSE_QUERY_KEY = ["license"] as const;

export function useLicense() {
  return useQuery<LicenseStatus>({
    queryKey: LICENSE_QUERY_KEY,
    queryFn: () => apiFetch<LicenseStatus>("/v1/license"),
  });
}

export function useActivateLicense() {
  const qc = useQueryClient();
  return useMutation<LicenseStatus, Error, { token: string }>({
    mutationFn: (body) =>
      apiFetch<LicenseStatus>("/v1/license", { method: "PUT", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: LICENSE_QUERY_KEY }),
  });
}

export function useRemoveLicense() {
  const qc = useQueryClient();
  return useMutation<LicenseStatus, Error, void>({
    mutationFn: () => apiFetch<LicenseStatus>("/v1/license", { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: LICENSE_QUERY_KEY }),
  });
}
