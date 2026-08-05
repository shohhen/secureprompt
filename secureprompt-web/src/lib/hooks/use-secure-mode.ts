"use client";

/**
 * TanStack Query hooks for /v1/secure-mode and the token vault.
 *
 * GET — any authenticated role; returns current workspace config.
 * PUT — admin only on the backend; the dashboard mirrors that by disabling
 *       the form when `session.role` is not admin/owner.
 *
 * WS6-4: on the generated client. The hand-written `SecureModeResponse` was
 * missing `sidecar_unavailable` (WS2-3), `capture_raw_content` (WS3-1) and
 * `raw_capture_retention_days` (WS3-2) — three security-posture fields the
 * handler round-trips, so `SecureModeUpdate`, being `Partial<Omit<…>>` of it,
 * could not express them either.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { makeApiClient, unwrap, type ApiError } from "@/lib/api-client";
import type { components } from "@/types/api.gen";

export type SecureModeResponse = components["schemas"]["SecureMode"];
export type SecureModeLevel = SecureModeResponse["level"];
export type SecureModeUpdate = components["schemas"]["SecureModeRequest"];

export type TokenizeRequest = components["schemas"]["TokenizeRequest"];
export type TokenizeResponse = components["schemas"]["TokenizeResponse"];
export type DetokenizeRequest = components["schemas"]["DetokenizeRequest"];
export type DetokenizeResponse = components["schemas"]["DetokenizeResponse"];

export function useSecureMode() {
  return useQuery<SecureModeResponse, ApiError>({
    queryKey: ["secure-mode"],
    queryFn: () => unwrap(makeApiClient().GET("/v1/secure-mode")),
  });
}

export function useUpdateSecureMode() {
  const qc = useQueryClient();
  return useMutation<SecureModeResponse, ApiError, SecureModeUpdate>({
    mutationFn: (body) =>
      unwrap(makeApiClient().PUT("/v1/secure-mode", { body })),
    onSuccess: (data) => {
      qc.setQueryData(["secure-mode"], data);
    },
  });
}

export function useTokenize() {
  return useMutation<TokenizeResponse, ApiError, TokenizeRequest>({
    mutationFn: (body) =>
      unwrap(makeApiClient().POST("/v1/secure-mode/tokenize", { body })),
  });
}

export function useDetokenize() {
  return useMutation<DetokenizeResponse, ApiError, DetokenizeRequest>({
    mutationFn: (body) =>
      unwrap(makeApiClient().POST("/v1/secure-mode/detokenize", { body })),
  });
}
