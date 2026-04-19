"use client";

/**
 * Phase 5 / Plan 05-04 — TanStack Query hooks for /v1/requests.
 *
 * useRequests: cursor-paginated list with nuqs filter state.
 * useRequestDetail: single request detail by id.
 */

import { useQuery, useInfiniteQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";

export interface RequestListItem {
  request_id: string;
  workspace_id: string;
  provider: string;
  model: string;
  final_action: string;
  input_tokens: number | null;
  output_tokens: number | null;
  cost_usd: number;
  has_violation: boolean;
  created_at: string;
}

export interface PolicyEventSummary {
  rule_id: string;
  rule_name: string;
  action: string;
  dry_run: boolean;
}

export interface RequestDetail {
  request_id: string;
  workspace_id: string;
  provider: string;
  model: string;
  final_action: string;
  input_tokens: number | null;
  output_tokens: number | null;
  reasoning_tokens: number | null;
  cache_read_tokens: number | null;
  cache_write_tokens: number | null;
  cost_usd: number;
  created_at: string;
  policy_events: PolicyEventSummary[];
}

export interface ListRequestsResponse {
  items: RequestListItem[];
  next_cursor: string | null;
}

export interface RequestsFilters {
  workspaceId: string;
  from?: string;
  to?: string;
  model?: string;
  has_violation?: boolean;
  limit?: number;
}

function buildRequestsUrl(filters: RequestsFilters, cursor?: string): string {
  const params = new URLSearchParams();
  params.set("workspace_id", filters.workspaceId);
  if (filters.from) params.set("from", filters.from);
  if (filters.to) params.set("to", filters.to);
  if (filters.model) params.set("model", filters.model);
  if (filters.has_violation != null)
    params.set("has_violation", String(filters.has_violation));
  if (filters.limit) params.set("limit", String(filters.limit));
  if (cursor) params.set("cursor", cursor);
  return `/v1/requests?${params.toString()}`;
}

/** Infinite-scroll hook for the requests list. */
export function useRequests(filters: RequestsFilters) {
  return useInfiniteQuery<ListRequestsResponse>({
    queryKey: ["requests", filters],
    queryFn: ({ pageParam }) =>
      apiFetch<ListRequestsResponse>(
        buildRequestsUrl(filters, pageParam as string | undefined)
      ),
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    initialPageParam: undefined,
  });
}

/** Single request detail. */
export function useRequestDetail(requestId: string, workspaceId: string) {
  return useQuery<RequestDetail>({
    queryKey: ["request-detail", requestId],
    queryFn: () => apiFetch<RequestDetail>(`/v1/requests/${requestId}`),
    enabled: Boolean(requestId && workspaceId),
  });
}
