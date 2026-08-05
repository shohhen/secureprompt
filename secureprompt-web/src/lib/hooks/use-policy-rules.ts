"use client";

/**
 * Phase 5 / Plan 05-04 — TanStack Query hooks for /v1/policy-rules.
 *
 * WS6-4: on the generated client. `action` is now the generated `PolicyAction`
 * union (`deny|allow|redact|transform|flag`) rather than a bare `string`, so a
 * typo in a rule form is a compile error.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { makeApiClient, unwrap, type ApiError } from "@/lib/api-client";
import type { components } from "@/types/api.gen";

export type PolicyRuleResponse = components["schemas"]["PolicyRuleResponse"];
export type CreateRuleBody = components["schemas"]["CreateRuleRequest"];
export type UpdateRuleBody = components["schemas"]["UpdateRuleRequest"];

export function usePolicyRules() {
  return useQuery<PolicyRuleResponse[], ApiError>({
    queryKey: ["policy-rules"],
    queryFn: () => unwrap(makeApiClient().GET("/v1/policy-rules")),
  });
}

export function useCreatePolicyRule() {
  const qc = useQueryClient();
  return useMutation<PolicyRuleResponse, ApiError, CreateRuleBody>({
    mutationFn: (body) =>
      unwrap(makeApiClient().POST("/v1/policy-rules", { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy-rules"] }),
  });
}

export function useUpdatePolicyRule() {
  const qc = useQueryClient();
  return useMutation<
    PolicyRuleResponse,
    ApiError,
    { id: string } & UpdateRuleBody
  >({
    mutationFn: ({ id, ...body }) =>
      unwrap(
        makeApiClient().PUT("/v1/policy-rules/{id}", {
          params: { path: { id } },
          body,
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy-rules"] }),
  });
}

export function useDeletePolicyRule() {
  const qc = useQueryClient();
  return useMutation<void, ApiError, string>({
    mutationFn: (id) =>
      unwrap(
        makeApiClient().DELETE("/v1/policy-rules/{id}", {
          params: { path: { id } },
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy-rules"] }),
  });
}

export function useTogglePolicyRuleEnabled() {
  const qc = useQueryClient();
  return useMutation<
    PolicyRuleResponse,
    ApiError,
    { id: string; value: boolean }
  >({
    mutationFn: ({ id, value }) =>
      unwrap(
        makeApiClient().PATCH("/v1/policy-rules/{id}/enabled", {
          params: { path: { id } },
          body: { value },
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy-rules"] }),
  });
}

export function useTogglePolicyRuleDryRun() {
  const qc = useQueryClient();
  return useMutation<
    PolicyRuleResponse,
    ApiError,
    { id: string; value: boolean }
  >({
    mutationFn: ({ id, value }) =>
      unwrap(
        makeApiClient().PATCH("/v1/policy-rules/{id}/dry-run", {
          params: { path: { id } },
          body: { value },
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy-rules"] }),
  });
}
