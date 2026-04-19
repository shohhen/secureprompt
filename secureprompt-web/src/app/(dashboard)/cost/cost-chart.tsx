"use client";

/**
 * Phase 5 / Plan 05-03 — Cost by model chart (client component).
 */

import { useQueryState } from "nuqs";
import { format, subDays } from "date-fns";
import { useCostByModel } from "@/lib/hooks/use-analytics";
import { BarChart } from "@/components/charts/bar-chart";
import { DateRangeFilter } from "@/components/filters/date-range-filter";
import { WorkspaceFilter } from "@/components/filters/workspace-filter";

const FORMAT = "yyyy-MM-dd";

interface CostChartProps {
  workspaceId: string;
}

export function CostChart({ workspaceId }: CostChartProps) {
  const [from] = useQueryState("from", {
    defaultValue: format(subDays(new Date(), 7), FORMAT),
  });
  const [to] = useQueryState("to", { defaultValue: format(new Date(), FORMAT) });

  const { data, isLoading, error } = useCostByModel({ from, to, workspaceId });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-4">
        <DateRangeFilter />
        <WorkspaceFilter workspaceId={workspaceId} />
      </div>

      {isLoading && (
        <p className="text-sm text-muted-foreground">Loading cost data…</p>
      )}
      {error && (
        <p className="text-sm text-destructive">
          Failed to load cost data. Marts may not be populated yet.
        </p>
      )}
      {data && data.length === 0 && !isLoading && (
        <p className="text-sm text-muted-foreground">
          No cost data for the selected period.
        </p>
      )}
      {data && data.length > 0 && (
        <BarChart
          data={data.map((r) => ({
            date: r.usage_date,
            daily_cost_usd: r.daily_cost_usd,
            rolling_7d_cost_usd: r.rolling_7d_cost_usd,
          }))}
          xKey="date"
          bars={[
            { key: "daily_cost_usd", label: "Daily cost (USD)", color: "#6366f1" },
            {
              key: "rolling_7d_cost_usd",
              label: "7-day rolling (USD)",
              color: "#f59e0b",
            },
          ]}
        />
      )}
    </div>
  );
}
