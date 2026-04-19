"use client";

/**
 * Phase 5 / Plan 05-04 — TanStack Query hooks for /v1/policy-rules.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";

export interface PolicyRuleResponse {
  id: string;
  workspace_id: string;
  name: string;
  priority: number;
  conditions: unknown;
  action: string;
  action_params: unknown;
  enabled: boolean;
  dry_run: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateRuleBody {
  name: string;
  priority: number;
  conditions?: unknown;
  action: string;
  action_params?: unknown;
  enabled?: boolean;
  dry_run?: boolean;
}

export interface UpdateRuleBody extends CreateRuleBody {}

export function usePolicyRules() {
  return useQuery<PolicyRuleResponse[]>({
    queryKey: ["policy-rules"],
    queryFn: () => apiFetch<PolicyRuleResponse[]>("/v1/policy-rules"),
  });
}

export function useCreatePolicyRule() {
  const qc = useQueryClient();
  return useMutation<PolicyRuleResponse, Error, CreateRuleBody>({
    mutationFn: (body) =>
      apiFetch<PolicyRuleResponse>("/v1/policy-rules", { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy-rules"] }),
  });
}

export function useUpdatePolicyRule() {
  const qc = useQueryClient();
  return useMutation<PolicyRuleResponse, Error, { id: string } & UpdateRuleBody>({
    mutationFn: ({ id, ...body }) =>
      apiFetch<PolicyRuleResponse>(`/v1/policy-rules/${id}`, {
        method: "PUT",
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy-rules"] }),
  });
}

export function useDeletePolicyRule() {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id) =>
      apiFetch<void>(`/v1/policy-rules/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy-rules"] }),
  });
}

export function useTogglePolicyRuleEnabled() {
  const qc = useQueryClient();
  return useMutation<PolicyRuleResponse, Error, { id: string; value: boolean }>({
    mutationFn: ({ id, value }) =>
      apiFetch<PolicyRuleResponse>(`/v1/policy-rules/${id}/enabled`, {
        method: "PATCH",
        body: { value },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy-rules"] }),
  });
}

export function useTogglePolicyRuleDryRun() {
  const qc = useQueryClient();
  return useMutation<PolicyRuleResponse, Error, { id: string; value: boolean }>({
    mutationFn: ({ id, value }) =>
      apiFetch<PolicyRuleResponse>(`/v1/policy-rules/${id}/dry-run`, {
        method: "PATCH",
        body: { value },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy-rules"] }),
  });
}
