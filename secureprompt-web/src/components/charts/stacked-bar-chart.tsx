"use client";

/**
 * Phase 5 / Plan 05-03 — Recharts stacked bar chart wrapper.
 * Used by the policy-violations page to show enforced vs dry-run counts.
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

interface StackedBarChartProps {
  data: Record<string, unknown>[];
  xKey: string;
  bars: { key: string; color?: string; label?: string }[];
  height?: number;
}

const DEFAULT_COLORS = [
  "#ef4444",
  "#f59e0b",
  "#6366f1",
  "#22c55e",
  "#3b82f6",
];

export function StackedBarChart({
  data,
  xKey,
  bars,
  height = 300,
}: StackedBarChartProps) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <ReBarChart
        data={data}
        margin={{ top: 8, right: 24, left: 0, bottom: 0 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
        <XAxis dataKey={xKey} tick={{ fontSize: 12 }} />
        <YAxis tick={{ fontSize: 12 }} />
        <Tooltip />
        <Legend />
        {bars.map((b, i) => (
          <Bar
            key={b.key}
            dataKey={b.key}
            name={b.label ?? b.key}
            fill={b.color ?? DEFAULT_COLORS[i % DEFAULT_COLORS.length]}
            stackId="stack"
          />
        ))}
      </ReBarChart>
    </ResponsiveContainer>
  );
}
