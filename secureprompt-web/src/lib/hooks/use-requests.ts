"use client";

/**
 * Phase 5 / Plan 05-04 — TanStack Query hooks for /v1/requests.
 *
 * useRequests: cursor-paginated list with nuqs filter state.
 * useRequestDetail: single request detail by id.
 */

import { useQuery } from "@tanstack/react-query";
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
  // Migration 002 — actor + transport context shown on the audit detail page.
  user_id: string | null;
  user_email: string | null;
  api_key_id: string | null;
  api_key_name: string | null;
  ip_address: string | null;
  user_agent: string | null;
  /** User-side checked content (latest user message, redacted). */
  redacted_prompt: string | null;
  /** AI-side checked content (response we returned, post-restore). */
  restored_response: string | null;
  /** Raw user input pre-redaction. */
  raw_prompt: string | null;
  /** Raw upstream output pre-restoration. */
  raw_response: string | null;
  /** Profile fields for the actor — `users.first_name/last_name/position`. */
  user_first_name: string | null;
  user_last_name: string | null;
  user_position: string | null;
  /** Self-reported MAC from the desktop wrapper. `null` for browser users. */
  user_device_mac: string | null;
  /** Coarse origin label derived from the user-agent (LibreChat, Browser,
   *  External API, …). `null` when no UA was sent. */
  source: string | null;
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

/**
 * Single-page cursor-paginated requests list.
 *
 * The previous infinite-scroll implementation hid the page boundary
 * entirely at low volume (16 rows + page size 50 = no "Load more"
 * button ever rendered, so users thought pagination was broken). This
 * hook returns one page at a time keyed by the caller-supplied cursor;
 * the table component owns the cursor stack for Prev/Next navigation.
 */
export function useRequestsPage(filters: RequestsFilters, cursor?: string) {
  return useQuery<ListRequestsResponse>({
    queryKey: ["requests-page", filters, cursor ?? "first"],
    queryFn: () =>
      apiFetch<ListRequestsResponse>(buildRequestsUrl(filters, cursor)),
    placeholderData: (prev) => prev,
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
