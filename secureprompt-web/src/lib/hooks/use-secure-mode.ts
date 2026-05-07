"use client";

/**
 * TanStack Query hooks for /v1/secure-mode.
 *
 * GET — any authenticated role; returns current workspace config.
 * PUT — admin only on the backend; the dashboard mirrors that by disabling
 *       the form when `session.role` is not admin/owner.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";

export type SecureModeLevel = "permissive" | "standard" | "strict";

export interface SecureModeResponse {
  workspace_id: string;
  enabled: boolean;
  level: SecureModeLevel;
  block_on_pii_detection: boolean;
  block_on_injection_detection: boolean;
  redact_pii_in_responses: boolean;
  updated_at: string;
}

export type SecureModeUpdate = Partial<
  Omit<SecureModeResponse, "workspace_id" | "updated_at">
>;

export function useSecureMode() {
  return useQuery<SecureModeResponse>({
    queryKey: ["secure-mode"],
    queryFn: () => apiFetch<SecureModeResponse>("/v1/secure-mode"),
  });
}

export function useUpdateSecureMode() {
  const qc = useQueryClient();
  return useMutation<SecureModeResponse, Error, SecureModeUpdate>({
    mutationFn: (body) =>
      apiFetch<SecureModeResponse>("/v1/secure-mode", { method: "PUT", body }),
    onSuccess: (data) => {
      qc.setQueryData(["secure-mode"], data);
    },
  });
}

export interface TokenizeRequest {
  text: string;
  entity_labels?: string[];
}

export interface TokenizeResponse {
  tokenized_text: string;
  token_vault_id: string;
  entity_counts: Record<string, number>;
}

export interface DetokenizeRequest {
  token_vault_id: string;
  text: string;
}

export interface DetokenizeResponse {
  text: string;
}

export function useTokenize() {
  return useMutation<TokenizeResponse, Error, TokenizeRequest>({
    mutationFn: (body) =>
      apiFetch<TokenizeResponse>("/v1/secure-mode/tokenize", {
        method: "POST",
        body,
      }),
  });
}

export function useDetokenize() {
  return useMutation<DetokenizeResponse, Error, DetokenizeRequest>({
    mutationFn: (body) =>
      apiFetch<DetokenizeResponse>("/v1/secure-mode/detokenize", {
        method: "POST",
        body,
      }),
  });
}
