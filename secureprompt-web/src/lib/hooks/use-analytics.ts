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

/** Hourly latency row returned when `bucket=hour`. Mirrors
 *  `LatencyPctilesHourlyRow` on the Rust side. Defined here rather than
 *  generated from OpenAPI because the schema regen lives in a separate
 *  PR; the runtime contract is what matters. */
export interface LatencyPctilesHourlyRow {
  workspace_id: string;
  model: string;
  bucket_ts: string; // ISO-Z timestamp
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  p50_ttft_ms: number;
  p95_ttft_ms: number;
  p99_ttft_ms: number;
  ttft_sample_count: number;
  sample_count: number;
}

/** Extended daily row — same schema as the OpenAPI-generated one with the
 *  three TTFT percentiles + sample count added. */
export interface LatencyPctilesDailyRow extends LatencyPctilesRow {
  p50_ttft_ms: number;
  p95_ttft_ms: number;
  p99_ttft_ms: number;
  ttft_sample_count: number;
}

export type LatencyPctilesResponse =
  | { bucket: "day"; rows: LatencyPctilesDailyRow[] }
  | { bucket: "hour"; rows: LatencyPctilesHourlyRow[] };

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

export interface LatencyParams extends DateRangeParams {
  /** `"day"` (default) returns daily mart rows; `"hour"` returns
   *  intra-day rows aggregated off the raw samples table. */
  bucket?: "day" | "hour";
}

export function useLatencyPctiles(params: LatencyParams) {
  return useQuery<LatencyPctilesResponse>({
    queryKey: ["analytics", "latency-pctiles", params],
    queryFn: async () => {
      const client = makeApiClient();
      const qs = new URLSearchParams({
        from: params.from,
        to: params.to,
        workspace_id: params.workspaceId,
        ...(params.model ? { model: params.model } : {}),
        ...(params.bucket ? { bucket: params.bucket } : {}),
      });
      const res = await client.GET(
        "/v1/analytics/latency-pctiles" as never,
        { params: { query: Object.fromEntries(qs) } } as never
      );
      if ((res as { error?: unknown }).error) {
        throw new Error("Failed to fetch latency-pctiles");
      }
      return (res as { data: LatencyPctilesResponse }).data;
    },
    enabled: Boolean(params.from && params.to && params.workspaceId),
  });
}
