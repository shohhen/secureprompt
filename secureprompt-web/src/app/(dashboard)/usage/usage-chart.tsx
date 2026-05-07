"use client";

/**
 * Phase 5 / Plan 05-03 — Usage daily chart (client component).
 *
 * Reads `from`, `to`, and `workspace_id` from URL state (nuqs) and fetches
 * `mart_usage_daily` data via TanStack Query.
 */

import { useQueryState } from "nuqs";
import { format, subDays } from "date-fns";
import { useUsageDaily } from "@/lib/hooks/use-analytics";
import { LineChart } from "@/components/charts/line-chart";
import { emptyDailySeries } from "@/components/charts/empty-range";
import { DateRangeFilter } from "@/components/filters/date-range-filter";
import { WorkspaceFilter } from "@/components/filters/workspace-filter";
import { formatDayTick } from "@/components/charts/format-axis";

const FORMAT = "yyyy-MM-dd";

interface UsageChartProps {
  workspaceId: string;
}

export function UsageChart({ workspaceId }: UsageChartProps) {
  const [from] = useQueryState("from", {
    defaultValue: format(subDays(new Date(), 7), FORMAT),
  });
  const [to] = useQueryState("to", { defaultValue: format(new Date(), FORMAT) });
  const [model] = useQueryState("model");

  const { data, isLoading, error } = useUsageDaily({
    from,
    to,
    workspaceId,
    model: model ?? undefined,
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-4">
        <DateRangeFilter />
        <WorkspaceFilter workspaceId={workspaceId} />
      </div>

      {isLoading && (
        <p className="text-sm text-muted-foreground">Loading usage data…</p>
      )}
      {error && (
        <p className="text-sm text-destructive">
          Failed to load usage data. Marts may not be populated yet.
        </p>
      )}

      {!error && (
        <div className="relative">
          <LineChart
            data={
              data && data.length > 0
                ? data.map((r) => ({
                    date: r.usage_date,
                    input_tokens: r.total_input_tokens,
                    output_tokens: r.total_output_tokens,
                    requests: r.request_count,
                  }))
                : emptyDailySeries(from, to, [
                    "input_tokens",
                    "output_tokens",
                    "requests",
                  ])
            }
            xKey="date"
            xTickFormatter={formatDayTick}
            tooltipLabelFormatter={formatDayTick}
            lines={[
              { key: "input_tokens", label: "Input tokens", color: "#6366f1" },
              { key: "output_tokens", label: "Output tokens", color: "#22c55e" },
              { key: "requests", label: "Requests", color: "#f59e0b" },
            ]}
          />
          {data && data.length === 0 && !isLoading && (
            <p className="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground pointer-events-none">
              No usage recorded for the selected period.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
