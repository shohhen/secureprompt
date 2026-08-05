"use client";

/**
 * Phase 5 / Plan 05-03 — Policy violations chart (client component).
 */

import { useQueryState } from "nuqs";
import { useTranslations } from "next-intl";
import { format, subDays } from "date-fns";
import { usePolicyViolations } from "@/lib/hooks/use-analytics";
import { StackedBarChart } from "@/components/charts/stacked-bar-chart";
import { emptyDailySeries } from "@/components/charts/empty-range";
import { DateRangeFilter } from "@/components/filters/date-range-filter";
import { WorkspaceFilter } from "@/components/filters/workspace-filter";
import { formatDayTick } from "@/components/charts/format-axis";

const FORMAT = "yyyy-MM-dd";

interface PolicyChartProps {
  workspaceId: string;
}

export function PolicyChart({ workspaceId }: PolicyChartProps) {
  const [from] = useQueryState("from", {
    defaultValue: format(subDays(new Date(), 7), FORMAT),
  });
  const [to] = useQueryState("to", { defaultValue: format(new Date(), FORMAT) });

  const t = useTranslations("policy");
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
          {t("loading")}
        </p>
      )}
      {error && (
        <p className="text-sm text-destructive">
          {t("loadFailed")}
        </p>
      )}

      {!error && (
        <div className="relative">
          <StackedBarChart
            data={
              data && data.length > 0
                ? data.map((r) => ({
                    date: r.violation_date,
                    rule: r.rule_name,
                    enforced: r.enforced_count,
                    dry_run: r.dry_run_count,
                  }))
                : emptyDailySeries(from, to, ["enforced", "dry_run"])
            }
            xKey="date"
            xTickFormatter={formatDayTick}
            tooltipLabelFormatter={formatDayTick}
            bars={[
              { key: "enforced", label: "Enforced", color: "#ef4444" },
              { key: "dry_run", label: "Dry-run", color: "#f59e0b" },
            ]}
          />
          {data && data.length === 0 && !isLoading && (
            <p className="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground pointer-events-none">
              {t("empty")}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
