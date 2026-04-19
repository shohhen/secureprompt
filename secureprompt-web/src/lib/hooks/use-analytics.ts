"use client";

/**
 * Phase 5 / Plan 05-03 — TanStack Query hooks for the four analytics marts.
 *
 * Each hook fetches from the Rust `/v1/analytics/*` routes.  The `workspaceId`
 * param is forwarded as `workspace_id` in the query string so the IDOR guard
 * on the server can verify it matches the JWT.
 */

import { useQuery } from "@tanstack/react-query";
import { makeApiClient } from "@/lib/api-client";
import type {
  UsageDailyRow,
  CostByModelRow,
  PolicyViolationsRow,
  LatencyPctilesRow,
} from "@/types/api";

export interface DateRangeParams {
  from: string; // ISO date "YYYY-MM-DD"
  to: string;
  workspaceId: string;
  model?: string;
}

// ── usage-daily ──────────────────────────────────────────────────────────────

export function useUsageDaily(params: DateRangeParams) {
  return useQuery<UsageDailyRow[]>({
    queryKey: ["analytics", "usage-daily", params],
    queryFn: async () => {
      const client = makeApiClient();
      const qs = new URLSearchParams({
        from: params.from,
        to: params.to,
        workspace_id: params.workspaceId,
        ...(params.model ? { model: params.model } : {}),
      });
      const res = await client.GET(
        "/v1/analytics/usage-daily" as never,
        { params: { query: Object.fromEntries(qs) } } as never
      );
      if ((res as { error?: unknown }).error) {
        throw new Error("Failed to fetch usage-daily");
      }
      return (res as { data: UsageDailyRow[] }).data;
    },
    enabled: Boolean(params.from && params.to && params.workspaceId),
  });
}

// ── cost-by-model ────────────────────────────────────────────────────────────

export function useCostByModel(params: DateRangeParams) {
  return useQuery<CostByModelRow[]>({
    queryKey: ["analytics", "cost-by-model", params],
    queryFn: async () => {
      const client = makeApiClient();
      const qs = new URLSearchParams({
        from: params.from,
        to: params.to,
        workspace_id: params.workspaceId,
      });
      const res = await client.GET(
        "/v1/analytics/cost-by-model" as never,
        { params: { query: Object.fromEntries(qs) } } as never
      );
      if ((res as { error?: unknown }).error) {
        throw new Error("Failed to fetch cost-by-model");
      }
      return (res as { data: CostByModelRow[] }).data;
    },
    enabled: Boolean(params.from && params.to && params.workspaceId),
  });
}

// ── policy-violations ────────────────────────────────────────────────────────

export function usePolicyViolations(params: DateRangeParams) {
  return useQuery<PolicyViolationsRow[]>({
    queryKey: ["analytics", "policy-violations", params],
    queryFn: async () => {
      const client = makeApiClient();
      const qs = new URLSearchParams({
        from: params.from,
        to: params.to,
        workspace_id: params.workspaceId,
      });
      const res = await client.GET(
        "/v1/analytics/policy-violations" as never,
        { params: { query: Object.fromEntries(qs) } } as never
      );
      if ((res as { error?: unknown }).error) {
        throw new Error("Failed to fetch policy-violations");
      }
      return (res as { data: PolicyViolationsRow[] }).data;
    },
    enabled: Boolean(params.from && params.to && params.workspaceId),
  });
}

// ── latency-pctiles ──────────────────────────────────────────────────────────

export function useLatencyPctiles(params: DateRangeParams) {
  return useQuery<LatencyPctilesRow[]>({
    queryKey: ["analytics", "latency-pctiles", params],
    queryFn: async () => {
      const client = makeApiClient();
      const qs = new URLSearchParams({
        from: params.from,
        to: params.to,
        workspace_id: params.workspaceId,
        ...(params.model ? { model: params.model } : {}),
      });
      const res = await client.GET(
        "/v1/analytics/latency-pctiles" as never,
        { params: { query: Object.fromEntries(qs) } } as never
      );
      if ((res as { error?: unknown }).error) {
        throw new Error("Failed to fetch latency-pctiles");
      }
      return (res as { data: LatencyPctilesRow[] }).data;
    },
    enabled: Boolean(params.from && params.to && params.workspaceId),
  });
}
