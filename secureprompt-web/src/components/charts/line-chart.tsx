"use client";

/**
 * Phase 5 / Plan 05-03 — Recharts line chart wrapper.
 *
 * Thin wrapper so page files stay free of direct Recharts imports and chart
 * styles can be updated in one place.
 */

import {
  LineChart as ReLineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

interface LineChartProps {
  data: Record<string, unknown>[];
  xKey: string;
  lines: { key: string; color?: string; label?: string }[];
  height?: number;
}

const DEFAULT_COLORS = [
  "#6366f1",
  "#22c55e",
  "#f59e0b",
  "#ef4444",
  "#3b82f6",
];

export function LineChart({ data, xKey, lines, height = 300 }: LineChartProps) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <ReLineChart data={data} margin={{ top: 8, right: 24, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
        <XAxis dataKey={xKey} tick={{ fontSize: 12 }} />
        <YAxis tick={{ fontSize: 12 }} />
        <Tooltip />
        <Legend />
        {lines.map((l, i) => (
          <Line
            key={l.key}
            type="monotone"
            dataKey={l.key}
            name={l.label ?? l.key}
            stroke={l.color ?? DEFAULT_COLORS[i % DEFAULT_COLORS.length]}
            dot={false}
            strokeWidth={2}
          />
        ))}
      </ReLineChart>
    </ResponsiveContainer>
  );
}
