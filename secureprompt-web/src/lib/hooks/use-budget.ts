"use client";

/**
 * Phase 5 / Plan 05-05 — TanStack Query hooks for /v1/workspaces/{id}/budgets.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";
import type { BudgetResponse, PutBudgetRequest } from "@/types/api";

export type { BudgetResponse, PutBudgetRequest };

export function useBudget(workspaceId: string) {
  return useQuery<BudgetResponse>({
    queryKey: ["budget", workspaceId],
    queryFn: () =>
      apiFetch<BudgetResponse>(`/v1/workspaces/${workspaceId}/budgets`),
    enabled: !!workspaceId,
  });
}

export function useUpdateBudget(workspaceId: string) {
  const qc = useQueryClient();
  return useMutation<BudgetResponse, Error, PutBudgetRequest>({
    mutationFn: (body) =>
      apiFetch<BudgetResponse>(`/v1/workspaces/${workspaceId}/budgets`, {
        method: "PUT",
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["budget", workspaceId] }),
  });
}
