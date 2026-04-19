"use client";

/**
 * Phase 5 / Plan 05-04 — TanStack Query hooks for /v1/providers.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";

export interface ProviderResponse {
  id: string;
  name: string;
  provider_type: string;
  has_credential: boolean;
  last_rotated_at: string;
  created_at: string;
}

export interface CreateProviderBody {
  name: string;
  provider_type: string;
  credential?: string;
}

export interface UpdateProviderBody {
  name?: string;
  provider_type?: string;
  credential?: string;
}

export function useProviders() {
  return useQuery<ProviderResponse[]>({
    queryKey: ["providers"],
    queryFn: () => apiFetch<ProviderResponse[]>("/v1/providers"),
  });
}

export function useCreateProvider() {
  const qc = useQueryClient();
  return useMutation<ProviderResponse, Error, CreateProviderBody>({
    mutationFn: (body) =>
      apiFetch<ProviderResponse>("/v1/providers", { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["providers"] }),
  });
}

export function useUpdateProvider() {
  const qc = useQueryClient();
  return useMutation<ProviderResponse, Error, { id: string } & UpdateProviderBody>({
    mutationFn: ({ id, ...body }) =>
      apiFetch<ProviderResponse>(`/v1/providers/${id}`, { method: "PUT", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["providers"] }),
  });
}

export function useDeleteProvider() {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id) =>
      apiFetch<void>(`/v1/providers/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["providers"] }),
  });
}
