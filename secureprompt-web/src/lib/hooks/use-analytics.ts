"use client";

/**
 * Phase 5 / Plan 05-03 — TanStack Query hooks for the four analytics marts.
 *
 * Each hook fetches from the Rust `/v1/analytics/*` routes. The `workspaceId`
 * param is forwarded as `workspace_id` in the query string so the IDOR guard
 * on the server can verify it matches the JWT.
 *
 * WS6-4 — this was the one hook already on `makeApiClient`, and it was on it
 * badly: every call went through `client.GET(path as never, opts as never)`,
 * which turns off the typing the client exists for, and every failure became
 * `throw new Error("Failed to fetch X")`, discarding the status the error
 * boundary branches on. Both were forced by the spec: `latency-pctiles` was
 * documented as a bare array when the handler returns a
 * `#[serde(tag = "bucket")]` envelope, so the generated types described
 * something the server never sends and the real shapes had to be hand-written
 * here. The document now matches the router, so the casts, the hand-written
 * row types and the error-flattening are all gone.
 */

import { useQuery } from "@tanstack/react-query";
import { makeApiClient, unwrap, type ApiError } from "@/lib/api-client";
import type {
  UsageDailyRow,
  CostByModelRow,
  PolicyViolationsRow,
  LatencyPctilesRow,
  LatencyPctilesHourlyRow,
  LatencyPctilesResponse,
} from "@/types/api";

export type {
  LatencyPctilesRow,
  LatencyPctilesHourlyRow,
  LatencyPctilesResponse,
};

export interface DateRangeParams {
  from: string; // ISO date "YYYY-MM-DD"
  to: string;
  workspaceId: string;
  model?: string;
}

// ── usage-daily ──────────────────────────────────────────────────────────────

export function useUsageDaily(params: DateRangeParams) {
  return useQuery<UsageDailyRow[], ApiError>({
    queryKey: ["analytics", "usage-daily", params],
    queryFn: () =>
      unwrap(
        makeApiClient().GET("/v1/analytics/usage-daily", {
          params: {
            query: {
              from: params.from,
              to: params.to,
              workspace_id: params.workspaceId,
              model: params.model,
            },
          },
        }),
      ),
    enabled: Boolean(params.from && params.to && params.workspaceId),
  });
}

// ── cost-by-model ────────────────────────────────────────────────────────────

export function useCostByModel(params: DateRangeParams) {
  return useQuery<CostByModelRow[], ApiError>({
    queryKey: ["analytics", "cost-by-model", params],
    queryFn: () =>
      unwrap(
        makeApiClient().GET("/v1/analytics/cost-by-model", {
          params: {
            query: {
              from: params.from,
              to: params.to,
              workspace_id: params.workspaceId,
            },
          },
        }),
      ),
    enabled: Boolean(params.from && params.to && params.workspaceId),
  });
}

// ── policy-violations ────────────────────────────────────────────────────────

export function usePolicyViolations(params: DateRangeParams) {
  return useQuery<PolicyViolationsRow[], ApiError>({
    queryKey: ["analytics", "policy-violations", params],
    queryFn: () =>
      unwrap(
        makeApiClient().GET("/v1/analytics/policy-violations", {
          params: {
            query: {
              from: params.from,
              to: params.to,
              workspace_id: params.workspaceId,
            },
          },
        }),
      ),
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
  return useQuery<LatencyPctilesResponse, ApiError>({
    queryKey: ["analytics", "latency-pctiles", params],
    queryFn: () =>
      unwrap(
        makeApiClient().GET("/v1/analytics/latency-pctiles", {
          params: {
            query: {
              from: params.from,
              to: params.to,
              workspace_id: params.workspaceId,
              model: params.model,
              bucket: params.bucket,
            },
          },
        }),
      ),
    enabled: Boolean(params.from && params.to && params.workspaceId),
  });
}
