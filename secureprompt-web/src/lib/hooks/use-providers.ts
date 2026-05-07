"use client";

/**
 * Phase 5 / Plan 05-04 — TanStack Query hooks for /v1/providers.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";

export interface ModelSummary {
  id: string;
  name: string;
}

export interface ProviderResponse {
  id: string;
  name: string;
  provider_type: string;
  has_credential: boolean;
  last_rotated_at: string;
  created_at: string;
  /** Models registered against this provider. Empty when none configured;
   *  the LibreChat fork's discovery client falls back to per-type defaults
   *  in that case. */
  models?: ModelSummary[];
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

export interface TestConnectionResult {
  success: boolean;
  /** Number of models the provider returned. Undefined when the test failed. */
  model_count?: number;
  /** Short, human-readable failure reason. */
  error?: string;
}

export interface TestUnsavedBody {
  provider_type: string;
  credential: string;
  base_url?: string;
}

/**
 * Test a provider credential BEFORE it's saved. Used by the "Test
 * Connection" button on the create/edit form so admins can verify the
 * key works before persisting it.
 */
export function useTestProviderConnection() {
  return useMutation<TestConnectionResult, Error, TestUnsavedBody>({
    mutationFn: (body) =>
      apiFetch<TestConnectionResult>("/v1/providers/test-connection", {
        method: "POST",
        body,
      }),
  });
}

/**
 * Test a provider credential that's ALREADY been saved (decrypts the
 * stored ciphertext via KMS server-side, probes the upstream). Useful
 * to verify rotation / expiration without exposing the plaintext.
 */
export function useTestStoredProviderConnection() {
  return useMutation<TestConnectionResult, Error, string>({
    mutationFn: (id) =>
      apiFetch<TestConnectionResult>(
        `/v1/providers/${id}/test-connection`,
        { method: "POST" },
      ),
  });
}

// ── Per-provider model registration ──────────────────────────────────────────

export function useProviderModels(providerId: string | undefined) {
  return useQuery<ModelSummary[]>({
    queryKey: ["providerModels", providerId],
    enabled: !!providerId,
    queryFn: () => apiFetch<ModelSummary[]>(`/v1/providers/${providerId}/models`),
  });
}

export function useAddProviderModel(providerId: string) {
  const qc = useQueryClient();
  return useMutation<ModelSummary, Error, { name: string }>({
    mutationFn: (body) =>
      apiFetch<ModelSummary>(`/v1/providers/${providerId}/models`, {
        method: "POST",
        body,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["providerModels", providerId] });
      // Provider list response embeds the model list nestedly — refresh
      // it too so any other panel rendering provider.models updates.
      qc.invalidateQueries({ queryKey: ["providers"] });
    },
  });
}

export function useDeleteProviderModel(providerId: string) {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (name) =>
      apiFetch<void>(
        `/v1/providers/${providerId}/models/${encodeURIComponent(name)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["providerModels", providerId] });
      qc.invalidateQueries({ queryKey: ["providers"] });
    },
  });
}

export interface SyncModelsResponse {
  added: string[];
  kept: string[];
  total: number;
}

/**
 * Bulk-pull every chat-capable model the upstream provider exposes for
 * the stored credential and persist it into `provider_models`. Idempotent
 * (existing rows are kept, only new ids inserted). Used by the "Sync
 * from upstream" button on the Models panel and triggered automatically
 * by the backend after a credential is saved/rotated.
 */
export function useSyncProviderModels(providerId: string) {
  const qc = useQueryClient();
  return useMutation<SyncModelsResponse, Error, void>({
    mutationFn: () =>
      apiFetch<SyncModelsResponse>(
        `/v1/providers/${providerId}/models/sync`,
        { method: "POST" },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["providerModels", providerId] });
      qc.invalidateQueries({ queryKey: ["providers"] });
    },
  });
}
