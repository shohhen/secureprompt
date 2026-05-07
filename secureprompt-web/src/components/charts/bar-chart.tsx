"use client";

/**
 * Phase 5 / Plan 05-03 — Recharts bar chart wrapper.
 */

import {
  BarChart as ReBarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

interface BarChartProps {
  data: Record<string, unknown>[];
  xKey: string;
  bars: { key: string; color?: string; label?: string }[];
  height?: number;
  xTickFormatter?: (value: unknown) => string;
  tooltipLabelFormatter?: (value: unknown) => string;
  xAxisMinTickGap?: number;
}

const DEFAULT_COLORS = [
  "#6366f1",
  "#22c55e",
  "#f59e0b",
  "#ef4444",
  "#3b82f6",
];

export function BarChart({
  data,
  xKey,
  bars,
  height = 300,
  xTickFormatter,
  tooltipLabelFormatter,
  xAxisMinTickGap = 24,
}: BarChartProps) {
  const labelFn = tooltipLabelFormatter ?? xTickFormatter;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <ReBarChart data={data} margin={{ top: 8, right: 24, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
        <XAxis
          dataKey={xKey}
          tick={{ fontSize: 12 }}
          tickFormatter={xTickFormatter ? (v) => xTickFormatter(v) : undefined}
          minTickGap={xAxisMinTickGap}
        />
        <YAxis tick={{ fontSize: 12 }} />
        <Tooltip labelFormatter={labelFn ? (v) => labelFn(v) : undefined} />
        <Legend />
        {bars.map((b, i) => (
          <Bar
            key={b.key}
            dataKey={b.key}
            name={b.label ?? b.key}
            fill={b.color ?? DEFAULT_COLORS[i % DEFAULT_COLORS.length]}
          />
        ))}
      </ReBarChart>
    </ResponsiveContainer>
  );
}
