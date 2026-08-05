"use client";

/**
 * Phase 5 / Plan 05-05 — TanStack Query hooks for /v1/workspaces/{id}/budgets.
 *
 * WS6-4: on the generated client. `BudgetResponse` used to be hand-written in
 * `types/api.d.ts` and was missing `updated_at`, which the handler has always
 * returned.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { makeApiClient, unwrap, type ApiError } from "@/lib/api-client";
import type { BudgetResponse, PutBudgetRequest } from "@/types/api";

export type { BudgetResponse, PutBudgetRequest };

export function useBudget(workspaceId: string) {
  return useQuery<BudgetResponse, ApiError>({
    queryKey: ["budget", workspaceId],
    queryFn: () =>
      unwrap(
        makeApiClient().GET("/v1/workspaces/{id}/budgets", {
          params: { path: { id: workspaceId } },
        }),
      ),
    enabled: !!workspaceId,
  });
}

export function useUpdateBudget(workspaceId: string) {
  const qc = useQueryClient();
  return useMutation<BudgetResponse, ApiError, PutBudgetRequest>({
    mutationFn: (body) =>
      unwrap(
        makeApiClient().PUT("/v1/workspaces/{id}/budgets", {
          params: { path: { id: workspaceId } },
          body,
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["budget", workspaceId] }),
  });
}
