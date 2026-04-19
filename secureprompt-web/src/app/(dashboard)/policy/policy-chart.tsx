"use client";

/**
 * Phase 5 / Plan 05-03 — Policy violations chart (client component).
 */

import { useQueryState } from "nuqs";
import { format, subDays } from "date-fns";
import { usePolicyViolations } from "@/lib/hooks/use-analytics";
import { StackedBarChart } from "@/components/charts/stacked-bar-chart";
import { DateRangeFilter } from "@/components/filters/date-range-filter";
import { WorkspaceFilter } from "@/components/filters/workspace-filter";

const FORMAT = "yyyy-MM-dd";

interface PolicyChartProps {
  workspaceId: string;
}

export function PolicyChart({ workspaceId }: PolicyChartProps) {
  const [from] = useQueryState("from", {
    defaultValue: format(subDays(new Date(), 7), FORMAT),
  });
  const [to] = useQueryState("to", { defaultValue: format(new Date(), FORMAT) });

  const { data, isLoading, error } = usePolicyViolations({
    from,
    to,
    workspaceId,
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-4">
        <DateRangeFilter />
        <WorkspaceFilter workspaceId={workspaceId} />
      </div>

      {isLoading && (
        <p className="text-sm text-muted-foreground">
          Loading policy violations…
        </p>
      )}
      {error && (
        <p className="text-sm text-destructive">
          Failed to load policy data. Marts may not be populated yet.
        </p>
      )}
      {data && data.length === 0 && !isLoading && (
        <p className="text-sm text-muted-foreground">
          No policy violations in the selected period.
        </p>
      )}
      {data && data.length > 0 && (
        <StackedBarChart
          data={data.map((r) => ({
            date: r.violation_date,
            rule: r.rule_name,
            enforced: r.enforced_count,
            dry_run: r.dry_run_count,
          }))}
          xKey="date"
          bars={[
            { key: "enforced", label: "Enforced", color: "#ef4444" },
            { key: "dry_run", label: "Dry-run", color: "#f59e0b" },
          ]}
        />
      )}
    </div>
  );
}
