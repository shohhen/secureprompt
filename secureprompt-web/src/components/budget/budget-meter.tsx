"use client";

/**
 * Phase 5 / Plan 05-05 — BudgetMeter
 *
 * Renders a labelled progress bar showing tokens used vs. limit.
 * Used in the workspace budget settings page and optionally in the topbar.
 *
 * Props:
 *   label       — "Daily" or "Monthly"
 *   used        — current token count (from Redis)
 *   limit       — token limit (null = unlimited)
 *   behavior    — "block" | "warn" | "flag" (affects color when near limit)
 */

import { cn } from "@/lib/utils";
import { useTranslations } from "next-intl";

interface BudgetMeterProps {
  label: string;
  used: number;
  limit: number | null;
  behavior?: "block" | "warn" | "flag";
  className?: string;
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}k`;
  return String(n);
}

export function BudgetMeter({
  label,
  used,
  limit,
  behavior = "warn",
  className,
}: BudgetMeterProps) {
  const t = useTranslations("budget");
  const pct = limit !== null && limit > 0 ? Math.min((used / limit) * 100, 100) : null;

  const barColor =
    pct === null
      ? "bg-muted-foreground/30"
      : pct >= 100 && behavior === "block"
        ? "bg-destructive"
        : pct >= 90
          ? "bg-amber-500"
          : "bg-primary";

  return (
    <div className={cn("space-y-1", className)}>
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>{label}</span>
        {limit !== null ? (
          <span>
            {t("usedOfLimit", { used: formatTokens(used), limit: formatTokens(limit) })}
          </span>
        ) : (
          <span>{t("usedUnlimited", { used: formatTokens(used) })}</span>
        )}
      </div>
      <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
        {pct !== null ? (
          <div
            className={cn("h-full rounded-full transition-all", barColor)}
            style={{ width: `${pct}%` }}
            role="progressbar"
            aria-valuenow={used}
            aria-valuemax={limit ?? undefined}
            aria-label={t("meterLabel", { label })}
          />
        ) : (
          <div
            className="h-full w-full rounded-full bg-muted-foreground/20"
            role="progressbar"
            aria-label={t("meterLabelNoLimit", { label })}
          />
        )}
      </div>
    </div>
  );
}
