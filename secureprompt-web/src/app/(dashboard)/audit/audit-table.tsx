"use client";

/**
 * Audit / request log.
 *
 * Cursor-paginated list with explicit Prev/Next controls. The previous
 * useInfiniteQuery + "Load more" approach hid the page boundary entirely
 * at low volume — pagination only became visible past 50 rows. This
 * version owns a cursor stack: Next pushes the server-returned cursor,
 * Prev pops, so workspaces with as few as `PAGE_SIZE+1` rows still
 * exercise pagination.
 */

import { useState } from "react";
import { useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { useRequestsPage } from "@/lib/hooks/use-requests";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";

interface Props {
  workspaceId: string;
}

const PAGE_SIZE = 25;

const ACTION_VARIANT: Record<
  string,
  "default" | "secondary" | "destructive" | "outline"
> = {
  allow: "secondary",
  redact: "outline",
  block: "destructive",
  deny: "destructive",
};

export function AuditTable({ workspaceId }: Props) {
  const router = useRouter();
  const t = useTranslations("audit");
  const [violationsOnly, setViolationsOnly] = useState(false);
  // Stack of cursors visited. Empty = page 1. push = Next, pop = Prev.
  // The cursor is what the *current* page was loaded with — so the
  // current page index is `cursorStack.length` (0-indexed → display +1).
  const [cursorStack, setCursorStack] = useState<string[]>([]);

  const currentCursor = cursorStack[cursorStack.length - 1];

  const filters = {
    workspaceId,
    limit: PAGE_SIZE,
    ...(violationsOnly ? { has_violation: true } : {}),
  };

  // Reset to page 1 when filters change. We tag the query key with the
  // current cursor so toggling the filter automatically refetches.
  const onFilterChange = (next: boolean) => {
    setViolationsOnly(next);
    setCursorStack([]);
  };

  const { data, isLoading, isFetching, error } = useRequestsPage(
    filters,
    currentCursor,
  );

  const rows = data?.items ?? [];
  const pageNumber = cursorStack.length + 1;
  const hasNext = Boolean(data?.next_cursor);
  const hasPrev = cursorStack.length > 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Switch
            checked={violationsOnly}
            onCheckedChange={onFilterChange}
            aria-label={t("onlyViolations")}
          />
          <Label>{t("onlyViolations")}</Label>
        </div>
        <p className="text-xs text-muted-foreground">
          {t("pageIndicator", { page: pageNumber })}
          {violationsOnly ? t("pageIndicatorViolations") : ""}
          {isFetching ? t("pageIndicatorLoading") : ""}
        </p>
      </div>

      {isLoading && (
        <p className="text-sm text-muted-foreground">{t("loading")}</p>
      )}
      {error && (
        <p className="text-sm text-destructive">{t("loadFailed")}</p>
      )}

      {!isLoading && !error && (
        <div className="rounded-md border overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="px-4 py-3 text-left font-medium">{t("colTime")}</th>
                <th className="px-4 py-3 text-left font-medium">{t("colProvider")}</th>
                <th className="px-4 py-3 text-left font-medium">{t("colModel")}</th>
                <th className="px-4 py-3 text-left font-medium">{t("colAction")}</th>
                <th className="px-4 py-3 text-left font-medium">{t("colViolation")}</th>
                <th className="px-4 py-3 text-right font-medium">{t("colIn")}</th>
                <th className="px-4 py-3 text-right font-medium">{t("colOut")}</th>
                <th className="px-4 py-3 text-right font-medium">{t("colCost")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td
                    colSpan={8}
                    className="px-4 py-10 text-center text-sm text-muted-foreground"
                  >
                    {violationsOnly ? t("emptyViolations") : t("empty")}
                  </td>
                </tr>
              )}
              {rows.map((r) => (
                <tr
                  key={r.request_id}
                  className="border-b last:border-0 hover:bg-muted/30 cursor-pointer transition-colors"
                  onClick={() => router.push(`/audit/${r.request_id}`)}
                >
                  <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">
                    {new Date(r.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{r.provider}</td>
                  <td className="px-4 py-3 font-mono text-xs">{r.model}</td>
                  <td className="px-4 py-3">
                    <Badge
                      variant={
                        ACTION_VARIANT[r.final_action.toLowerCase()] ?? "outline"
                      }
                    >
                      {r.final_action}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    {r.has_violation ? (
                      <Badge variant="destructive">{t("violation")}</Badge>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right text-muted-foreground">
                    {r.input_tokens ?? "—"}
                  </td>
                  <td className="px-4 py-3 text-right text-muted-foreground">
                    {r.output_tokens ?? "—"}
                  </td>
                  <td className="px-4 py-3 text-right text-muted-foreground">
                    {r.cost_usd.toFixed(4)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(hasPrev || hasNext) && (
        <div className="flex items-center justify-between">
          <Button
            variant="outline"
            size="sm"
            disabled={!hasPrev || isFetching}
            onClick={() => setCursorStack((s) => s.slice(0, -1))}
          >
            {t("previous")}
          </Button>
          <span className="text-xs text-muted-foreground">
            {t("pageAndRows", { page: pageNumber, count: rows.length })}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={!hasNext || isFetching}
            onClick={() => {
              const next = data?.next_cursor;
              if (next) setCursorStack((s) => [...s, next]);
            }}
          >
            {t("next")}
          </Button>
        </div>
      )}
    </div>
  );
}
