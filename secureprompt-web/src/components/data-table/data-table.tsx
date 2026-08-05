"use client";

/**
 * Phase 5 / Plan 05-04 — Generic TanStack Table v8 wrapper.
 *
 * Usage:
 *   <DataTable columns={columns} data={rows} />
 *
 * Renders a full-width table with sticky header, zebra stripes, and an
 * optional empty-state slot. No dangerouslySetInnerHTML anywhere.
 */

import { useTranslations } from "next-intl";
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table";

interface DataTableProps<TData> {
  columns: ColumnDef<TData>[];
  data: TData[];
  /** Already-translated copy. Falls back to `common.noResults`. */
  emptyMessage?: string;
  isLoading?: boolean;
}

export function DataTable<TData>({
  columns,
  data,
  emptyMessage,
  isLoading = false,
}: DataTableProps<TData>) {
  const t = useTranslations("common");
  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  return (
    <div className="w-full overflow-x-auto rounded-md border">
      <table className="w-full text-sm">
        <thead className="bg-muted/50 sticky top-0">
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id}>
              {hg.headers.map((h) => (
                <th
                  key={h.id}
                  className="px-4 py-2 text-left font-medium text-muted-foreground whitespace-nowrap"
                >
                  {h.isPlaceholder
                    ? null
                    : flexRender(h.column.columnDef.header, h.getContext())}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {isLoading ? (
            <tr>
              <td
                colSpan={columns.length}
                className="py-8 text-center text-muted-foreground"
              >
                {t("loading")}
              </td>
            </tr>
          ) : table.getRowModel().rows.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length}
                className="py-8 text-center text-muted-foreground"
              >
                {emptyMessage ?? t("noResults")}
              </td>
            </tr>
          ) : (
            table.getRowModel().rows.map((row) => (
              <tr
                key={row.id}
                className="border-t hover:bg-muted/30 transition-colors odd:bg-background even:bg-muted/10"
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="px-4 py-2 align-middle">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
