"use client";

/**
 * Phase 5 / Plan 05-04 — TanStack Query hooks for /v1/keys.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";

export interface KeyResponse {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  revoked_at: string | null;
  /** Set when the key was assigned to a workspace member (009 migration). */
  assigned_user_id?: string | null;
}

export interface CreateKeyResponse {
  id: string;
  name: string;
  /** Full plaintext — shown once, flushed on dialog close. */
  api_key: string;
  prefix: string;
  created_at: string;
  assigned_user_id?: string | null;
}

export interface CreateKeyBody {
  name: string;
  /** When set, the key is assigned to this workspace member; the plaintext
   *  is encrypted-at-rest so the LibreChat backend can fetch it
   *  server-to-server (member never types or sees it). */
  user_id?: string;
}

export function useKeys() {
  return useQuery<KeyResponse[]>({
    queryKey: ["keys"],
    queryFn: () => apiFetch<KeyResponse[]>("/v1/keys"),
  });
}

export function useCreateKey() {
  const qc = useQueryClient();
  return useMutation<CreateKeyResponse, Error, CreateKeyBody>({
    mutationFn: (body) =>
      apiFetch<CreateKeyResponse>("/v1/keys", { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["keys"] }),
  });
}

export function useRevokeKey() {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id) =>
      apiFetch<void>(`/v1/keys/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["keys"] }),
  });
}
