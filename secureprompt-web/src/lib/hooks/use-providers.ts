"use client";

/**
 * Phase 5 / Plan 05-04 — TanStack Query hooks for /v1/providers.
 *
 * WS6-4: on the generated client. Nine of the eleven routes this file calls
 * were undocumented until this workstream — `test-connection` (both forms) and
 * the whole `/models` sub-tree — so every request and response shape here was
 * hand-written. They come from the codegen now.
 *
 * `config` (Vertex AI's `{ region, project }`) is the field whose absence from
 * the spec kept `check-openapi-codegen.sh` unwired; see the note above
 * `ProviderResponse` in openapi.yaml for why it was restored rather than
 * dropped.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { makeApiClient, unwrap, type ApiError } from "@/lib/api-client";
import type { components } from "@/types/api.gen";

export type ModelSummary = components["schemas"]["ModelSummary"];
export type ProviderResponse = components["schemas"]["ProviderResponse"];
export type CreateProviderBody =
  components["schemas"]["CreateProviderRequest"];
export type UpdateProviderBody =
  components["schemas"]["UpdateProviderRequest"];
export type TestConnectionResult =
  components["schemas"]["TestConnectionResult"];
export type TestUnsavedBody = components["schemas"]["TestConnectionRequest"];
export type SyncModelsResponse = components["schemas"]["SyncModelsResponse"];
export type BulkDeleteModelsResponse =
  components["schemas"]["BulkDeleteModelsResponse"];

export function useProviders() {
  return useQuery<ProviderResponse[], ApiError>({
    queryKey: ["providers"],
    queryFn: () => unwrap(makeApiClient().GET("/v1/providers")),
  });
}

export function useCreateProvider() {
  const qc = useQueryClient();
  return useMutation<ProviderResponse, ApiError, CreateProviderBody>({
    mutationFn: (body) =>
      unwrap(makeApiClient().POST("/v1/providers", { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["providers"] }),
  });
}

export function useUpdateProvider() {
  const qc = useQueryClient();
  return useMutation<
    ProviderResponse,
    ApiError,
    { id: string } & UpdateProviderBody
  >({
    mutationFn: ({ id, ...body }) =>
      unwrap(
        makeApiClient().PUT("/v1/providers/{id}", {
          params: { path: { id } },
          body,
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["providers"] }),
  });
}

export function useDeleteProvider() {
  const qc = useQueryClient();
  return useMutation<void, ApiError, string>({
    mutationFn: (id) =>
      unwrap(
        makeApiClient().DELETE("/v1/providers/{id}", {
          params: { path: { id } },
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["providers"] }),
  });
}

/**
 * Test a provider credential BEFORE it's saved. Used by the "Test
 * Connection" button on the create/edit form so admins can verify the
 * key works before persisting it.
 */
export function useTestProviderConnection() {
  return useMutation<TestConnectionResult, ApiError, TestUnsavedBody>({
    mutationFn: (body) =>
      unwrap(makeApiClient().POST("/v1/providers/test-connection", { body })),
  });
}

/**
 * Test a provider credential that's ALREADY been saved (decrypts the
 * stored ciphertext via KMS server-side, probes the upstream). Useful
 * to verify rotation / expiration without exposing the plaintext.
 */
export function useTestStoredProviderConnection() {
  return useMutation<TestConnectionResult, ApiError, string>({
    mutationFn: (id) =>
      unwrap(
        makeApiClient().POST("/v1/providers/{id}/test-connection", {
          params: { path: { id } },
        }),
      ),
  });
}

// ── Per-provider model registration ──────────────────────────────────────────

export function useProviderModels(providerId: string | undefined) {
  return useQuery<ModelSummary[], ApiError>({
    queryKey: ["providerModels", providerId],
    enabled: !!providerId,
    queryFn: () =>
      unwrap(
        makeApiClient().GET("/v1/providers/{id}/models", {
          params: { path: { id: providerId as string } },
        }),
      ),
  });
}

export function useAddProviderModel(providerId: string) {
  const qc = useQueryClient();
  return useMutation<ModelSummary, ApiError, { name: string }>({
    mutationFn: (body) =>
      unwrap(
        makeApiClient().POST("/v1/providers/{id}/models", {
          params: { path: { id: providerId } },
          body,
        }),
      ),
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
  return useMutation<void, ApiError, string>({
    mutationFn: (name) =>
      unwrap(
        // openapi-fetch percent-encodes path params itself, so the explicit
        // encodeURIComponent the hand-rolled URL needed is gone. A model name
        // containing "/" is still encoded, verified against the same route.
        makeApiClient().DELETE("/v1/providers/{id}/models/{name}", {
          params: { path: { id: providerId, name } },
        }),
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["providerModels", providerId] });
      qc.invalidateQueries({ queryKey: ["providers"] });
    },
  });
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
  return useMutation<SyncModelsResponse, ApiError, void>({
    mutationFn: () =>
      unwrap(
        makeApiClient().POST("/v1/providers/{id}/models/sync", {
          params: { path: { id: providerId } },
        }),
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["providerModels", providerId] });
      qc.invalidateQueries({ queryKey: ["providers"] });
    },
  });
}

/**
 * Soft-delete many models in one request (the "Delete selected" action).
 * Removed models are excluded from re-sync, so the deletion sticks across
 * credential rotations and "Sync from upstream".
 */
export function useBulkDeleteProviderModels(providerId: string) {
  const qc = useQueryClient();
  return useMutation<BulkDeleteModelsResponse, ApiError, string[]>({
    mutationFn: (names) =>
      unwrap(
        makeApiClient().POST("/v1/providers/{id}/models/bulk-delete", {
          params: { path: { id: providerId } },
          body: { names },
        }),
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["providerModels", providerId] });
      qc.invalidateQueries({ queryKey: ["providers"] });
    },
  });
}
