"use client";

/**
 * Latency + TTFT percentiles chart.
 *
 * Two visible series groups:
 *   - End-to-end gateway latency (p50/p95/p99) — what the request took
 *     from arrival at SecurePrompt to a response being ready.
 *   - TTFT (time-to-first-byte) — how quickly the upstream provider
 *     started responding. The gap between TTFT and total latency is the
 *     gateway's own pre-flight overhead (policy + redaction + setup).
 *
 * Granularity:
 *   - "day" buckets are the dbt mart's primary grain — fastest, used by
 *     default for ranges > 24h.
 *   - "hour" buckets aggregate the raw `latency_samples` table for
 *     intra-day drilldown. Capped at 31 days server-side.
 */

import { useMemo } from "react";
import { useTranslations } from "next-intl";
import { useQueryState } from "nuqs";
import { format, subDays } from "date-fns";
import {
  useLatencyPctiles,
  type LatencyPctilesResponse,
} from "@/lib/hooks/use-analytics";
import { LineChart } from "@/components/charts/line-chart";
import {
  emptyDailySeries,
  emptyHourlySeries,
} from "@/components/charts/empty-range";
import { DateRangeFilter } from "@/components/filters/date-range-filter";
import { WorkspaceFilter } from "@/components/filters/workspace-filter";
import { formatDayTick, formatHourTick } from "@/components/charts/format-axis";

const FORMAT = "yyyy-MM-dd";

interface LatencyChartProps {
  workspaceId: string;
}

const FIELDS = ["p50", "p95", "p99", "ttft_p50", "ttft_p95", "ttft_p99"];

export function LatencyChart({ workspaceId }: LatencyChartProps) {
  const [from] = useQueryState("from", {
    defaultValue: format(subDays(new Date(), 7), FORMAT),
  });
  const [to] = useQueryState("to", { defaultValue: format(new Date(), FORMAT) });
  const [model] = useQueryState("model");
  const [bucket, setBucket] = useQueryState("bucket", { defaultValue: "day" });

  const t = useTranslations("latency");
  const { data, isLoading, error } = useLatencyPctiles({
    from,
    to,
    workspaceId,
    model: model ?? undefined,
    bucket: bucket === "hour" ? "hour" : "day",
  });

  const { rows, xKey, formatTick } = useMemo(
    () => buildChartData(data, bucket === "hour" ? "hour" : "day", from, to),
    [data, bucket, from, to],
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-4">
        <DateRangeFilter />
        <WorkspaceFilter workspaceId={workspaceId} />
        <div className="inline-flex rounded-md border border-border bg-background p-0.5 text-sm">
          {(["day", "hour"] as const).map((opt) => (
            <button
              key={opt}
              type="button"
              onClick={() => setBucket(opt)}
              className={
                "rounded px-3 py-1 transition-colors " +
                (bucket === opt
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground")
              }
            >
              {opt === "day" ? t("granularityDaily") : t("granularityHourly")}
            </button>
          ))}
        </div>
      </div>

      {isLoading && (
        <p className="text-sm text-muted-foreground">{t("loading")}</p>
      )}
      {error && (
        <p className="text-sm text-destructive">
          {t("loadFailed")}
        </p>
      )}

      {!error && (
        <div className="relative">
          <LineChart
            data={rows}
            xKey={xKey}
            xTickFormatter={formatTick}
            tooltipLabelFormatter={formatTick}
            xAxisMinTickGap={bucket === "hour" ? 48 : 16}
            lines={[
              { key: "p50", label: "Latency p50", color: "#22c55e" },
              { key: "p95", label: "Latency p95", color: "#f59e0b" },
              { key: "p99", label: "Latency p99", color: "#ef4444" },
              { key: "ttft_p50", label: "TTFT p50", color: "#60a5fa" },
              { key: "ttft_p95", label: "TTFT p95", color: "#3b82f6" },
              { key: "ttft_p99", label: "TTFT p99", color: "#1d4ed8" },
            ]}
          />
          {data && data.rows.length === 0 && !isLoading && (
            <p className="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground pointer-events-none">
              {t("empty")}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

interface ChartShape {
  rows: Record<string, string | number>[];
  xKey: string;
  formatTick: (v: unknown) => string;
}

function buildChartData(
  data: LatencyPctilesResponse | undefined,
  bucket: "day" | "hour",
  from: string,
  to: string,
): ChartShape {
  if (bucket === "hour") {
    const xKey = "bucket_ts";
    const rows =
      data && data.bucket === "hour" && data.rows.length > 0
        ? data.rows.map((r) => ({
            bucket_ts: r.bucket_ts,
            p50: r.p50_latency_ms,
            p95: r.p95_latency_ms,
            p99: r.p99_latency_ms,
            ttft_p50: r.p50_ttft_ms,
            ttft_p95: r.p95_ttft_ms,
            ttft_p99: r.p99_ttft_ms,
          }))
        : emptyHourlySeries(from, to, FIELDS);
    return { rows, xKey, formatTick: formatHourTick };
  }

  const xKey = "date";
  const rows =
    data && data.bucket === "day" && data.rows.length > 0
      ? data.rows.map((r) => ({
          date: r.usage_date,
          p50: r.p50_latency_ms,
          p95: r.p95_latency_ms,
          p99: r.p99_latency_ms,
          ttft_p50: r.p50_ttft_ms ?? 0,
          ttft_p95: r.p95_ttft_ms ?? 0,
          ttft_p99: r.p99_ttft_ms ?? 0,
        }))
      : emptyDailySeries(from, to, FIELDS);
  return { rows, xKey, formatTick: formatDayTick };
}

