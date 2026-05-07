"use client";

/**
 * Phase 5 / Plan 05-04 — Requests list with infinite scroll.
 *
 * Reads nuqs URL state (from/to/model/has_violation) and renders
 * useRequests() infinite query results in a DataTable with a
 * "Load more" button.
 */

import { useState } from "react";
import { useQueryState, parseAsString, parseAsBoolean } from "nuqs";
import { format, subDays } from "date-fns";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/data-table/data-table";
import { useRequestsPage, type RequestListItem } from "@/lib/hooks/use-requests";
import { Badge } from "@/components/ui/badge";
import Link from "next/link";

const DATE_FMT = "yyyy-MM-dd";

interface RequestsTableProps {
  workspaceId: string;
}

const columns: ColumnDef<RequestListItem>[] = [
  {
    accessorKey: "created_at",
    header: "Time",
    cell: ({ getValue }) => {
      const v = getValue<string>();
      return (
        <span className="text-xs text-muted-foreground whitespace-nowrap">
          {new Date(v).toLocaleString()}
        </span>
      );
    },
  },
  {
    accessorKey: "provider",
    header: "Provider",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs">{getValue<string>()}</span>
    ),
  },
  {
    accessorKey: "model",
    header: "Model",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs">{getValue<string>()}</span>
    ),
  },
  {
    accessorKey: "final_action",
    header: "Action",
    cell: ({ getValue }) => {
      const action = getValue<string>();
      const variant =
        action === "allow"
          ? "secondary"
          : action === "deny"
            ? "destructive"
            : "outline";
      return <Badge variant={variant}>{action}</Badge>;
    },
  },
  {
    accessorKey: "cost_usd",
    header: "Cost (USD)",
    cell: ({ getValue }) => (
      <span className="tabular-nums text-xs">${getValue<number>().toFixed(4)}</span>
    ),
  },
  {
    accessorKey: "has_violation",
    header: "Violation",
    cell: ({ getValue }) =>
      getValue<boolean>() ? (
        <Badge variant="destructive">Yes</Badge>
      ) : (
        <span className="text-muted-foreground text-xs">No</span>
      ),
  },
  {
    accessorKey: "request_id",
    header: "",
    cell: ({ getValue }) => (
      <Link
        href={`/requests/${getValue<string>()}`}
        className="text-xs text-primary underline-offset-2 hover:underline"
      >
        Details
      </Link>
    ),
  },
];

export function RequestsTable({ workspaceId }: RequestsTableProps) {
  const [from] = useQueryState(
    "from",
    parseAsString.withDefault(format(subDays(new Date(), 7), DATE_FMT)),
  );
  const [to] = useQueryState(
    "to",
    parseAsString.withDefault(format(new Date(), DATE_FMT)),
  );
  const [model] = useQueryState("model", parseAsString);
  const [hasViolation] = useQueryState("has_violation", parseAsBoolean);

  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const currentCursor = cursorStack[cursorStack.length - 1];

  const { data, isLoading, isFetching, error } = useRequestsPage(
    {
      workspaceId,
      from: from ?? undefined,
      to: to ?? undefined,
      model: model ?? undefined,
      has_violation: hasViolation ?? undefined,
      limit: 25,
    },
    currentCursor,
  );

  const rows: RequestListItem[] = data?.items ?? [];
  const hasNextPage = Boolean(data?.next_cursor);
  const hasPrev = cursorStack.length > 0;
  const isFetchingNextPage = isFetching;
  const handleLoadMore = () => {
    const next = data?.next_cursor;
    if (next) setCursorStack((s) => [...s, next]);
  };
  const handlePrev = () => setCursorStack((s) => s.slice(0, -1));

  return (
    <div className="space-y-4">
      {error && (
        <p className="text-sm text-destructive">
          Failed to load requests. The API may be unavailable.
        </p>
      )}
      <DataTable
        columns={columns}
        data={rows}
        isLoading={isLoading}
        emptyMessage="No requests found for the selected filters."
      />
      {(hasPrev || hasNextPage) && (
        <div className="flex items-center justify-between pt-2">
          <button
            onClick={handlePrev}
            disabled={!hasPrev || isFetchingNextPage}
            className="text-sm text-primary hover:underline disabled:opacity-50"
          >
            ← Previous
          </button>
          <button
            onClick={handleLoadMore}
            disabled={!hasNextPage || isFetchingNextPage}
            className="text-sm text-primary hover:underline disabled:opacity-50"
          >
            {isFetchingNextPage ? "Loading…" : "Next →"}
          </button>
        </div>
      )}
    </div>
  );
}
