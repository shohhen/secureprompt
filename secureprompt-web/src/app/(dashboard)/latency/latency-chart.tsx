"use client";

/**
 * Phase 5 / Plan 05-03 — Latency percentiles chart (client component).
 */

import { useQueryState } from "nuqs";
import { format, subDays } from "date-fns";
import { useLatencyPctiles } from "@/lib/hooks/use-analytics";
import { LineChart } from "@/components/charts/line-chart";
import { DateRangeFilter } from "@/components/filters/date-range-filter";
import { WorkspaceFilter } from "@/components/filters/workspace-filter";

const FORMAT = "yyyy-MM-dd";

interface LatencyChartProps {
  workspaceId: string;
}

export function LatencyChart({ workspaceId }: LatencyChartProps) {
  const [from] = useQueryState("from", {
    defaultValue: format(subDays(new Date(), 7), FORMAT),
  });
  const [to] = useQueryState("to", { defaultValue: format(new Date(), FORMAT) });
  const [model] = useQueryState("model");

  const { data, isLoading, error } = useLatencyPctiles({
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
        <p className="text-sm text-muted-foreground">
          Loading latency data…
        </p>
      )}
      {error && (
        <p className="text-sm text-destructive">
          Failed to load latency data. Marts may not be populated yet.
        </p>
      )}
      {data && data.length === 0 && !isLoading && (
        <p className="text-sm text-muted-foreground">
          No latency data for the selected period.
        </p>
      )}
      {data && data.length > 0 && (
        <LineChart
          data={data.map((r) => ({
            date: r.usage_date,
            p50: r.p50_latency_ms,
            p95: r.p95_latency_ms,
            p99: r.p99_latency_ms,
          }))}
          xKey="date"
          lines={[
            { key: "p50", label: "p50 (ms)", color: "#22c55e" },
            { key: "p95", label: "p95 (ms)", color: "#f59e0b" },
            { key: "p99", label: "p99 (ms)", color: "#ef4444" },
          ]}
        />
      )}
    </div>
  );
}
