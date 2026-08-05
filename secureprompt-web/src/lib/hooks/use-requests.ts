"use client";

/**
 * Phase 5 / Plan 05-04 — TanStack Query hooks for /v1/requests.
 *
 * useRequestsPage: cursor-paginated list.
 * useRequestDetail: single request detail by id.
 *
 * WS6-4: on the generated client. The 16 actor/content/provenance fields the
 * detail drawer renders were hand-declared here because the OpenAPI document
 * stopped at `policy_events`; they are documented now, so the type comes from
 * the codegen and `engines` (WS2-4 detection provenance) arrives with it.
 */

import { useQuery } from "@tanstack/react-query";
import { makeApiClient, unwrap, type ApiError } from "@/lib/api-client";
import type { components } from "@/types/api.gen";

export type RequestListItem = components["schemas"]["RequestListItem"];
export type PolicyEventSummary = components["schemas"]["PolicyEventSummary"];
export type RequestDetail = components["schemas"]["RequestDetail"];
export type ListRequestsResponse =
  components["schemas"]["ListRequestsResponse"];

export interface RequestsFilters {
  workspaceId: string;
  from?: string;
  to?: string;
  model?: string;
  has_violation?: boolean;
  limit?: number;
}

/**
 * The query object for `GET /v1/requests`.
 *
 * Built explicitly rather than by URL string concatenation: openapi-fetch
 * serialises `params.query` itself, and passing a pre-built querystring in the
 * path would defeat the typing that is the point of the migration. Undefined
 * entries are dropped by openapi-fetch, so the optional filters behave exactly
 * as the old `URLSearchParams` version did.
 */
function requestsQuery(filters: RequestsFilters, cursor?: string) {
  return {
    workspace_id: filters.workspaceId,
    from: filters.from,
    to: filters.to,
    model: filters.model,
    has_violation: filters.has_violation,
    limit: filters.limit,
    cursor,
  };
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
  return useQuery<ListRequestsResponse, ApiError>({
    queryKey: ["requests-page", filters, cursor ?? "first"],
    queryFn: () =>
      unwrap(
        makeApiClient().GET("/v1/requests", {
          params: { query: requestsQuery(filters, cursor) },
        }),
      ),
    placeholderData: (prev) => prev,
  });
}

/** Single request detail. */
export function useRequestDetail(requestId: string, workspaceId: string) {
  return useQuery<RequestDetail, ApiError>({
    queryKey: ["request-detail", requestId],
    queryFn: () =>
      unwrap(
        makeApiClient().GET("/v1/requests/{id}", {
          params: { path: { id: requestId } },
        }),
      ),
    enabled: Boolean(requestId && workspaceId),
  });
}
