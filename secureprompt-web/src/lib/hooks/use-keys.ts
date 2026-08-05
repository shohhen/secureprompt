"use client";

/**
 * Phase 5 / Plan 05-04 — TanStack Query hooks for /v1/keys.
 *
 * WS6-4: on the generated client. The three interfaces that used to live here
 * are now type aliases onto `api.gen.ts`, so `assigned_user_id` (migration
 * 009) and `user_id` on create cannot drift from the Rust structs again.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { makeApiClient, unwrap, type ApiError } from "@/lib/api-client";
import type { components } from "@/types/api.gen";

export type KeyResponse = components["schemas"]["KeyResponse"];
export type CreateKeyResponse = components["schemas"]["CreateKeyResponse"];
export type CreateKeyBody = components["schemas"]["CreateKeyRequest"];

export function useKeys() {
  return useQuery<KeyResponse[], ApiError>({
    queryKey: ["keys"],
    queryFn: () => unwrap(makeApiClient().GET("/v1/keys")),
  });
}

export function useCreateKey() {
  const qc = useQueryClient();
  return useMutation<CreateKeyResponse, ApiError, CreateKeyBody>({
    mutationFn: (body) => unwrap(makeApiClient().POST("/v1/keys", { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["keys"] }),
  });
}

export function useRevokeKey() {
  const qc = useQueryClient();
  return useMutation<void, ApiError, string>({
    mutationFn: (id) =>
      unwrap(
        makeApiClient().DELETE("/v1/keys/{id}", { params: { path: { id } } }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["keys"] }),
  });
}
