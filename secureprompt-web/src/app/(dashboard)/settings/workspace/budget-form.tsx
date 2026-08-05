"use client";

/**
 * Phase 5 / Plan 05-05 — Workspace Budget Form
 *
 * Inline editable form that fetches the current budget settings and allows
 * an admin to update daily/monthly token limits and the enforcement behavior.
 * A viewer can read the current usage but cannot save.
 */

import { useState, useEffect } from "react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";
import { useBudget, useUpdateBudget } from "@/lib/hooks/use-budget";
import { BudgetMeter } from "@/components/budget/budget-meter";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { BudgetBehavior } from "@/types/api";

interface BudgetFormProps {
  workspaceId: string;
}

/** Values only; label and description come from the `budgetSettings` namespace. */
const BEHAVIOR_OPTIONS: BudgetBehavior[] = ["block", "warn", "flag"];

function parseLimitInput(value: string): number | null {
  const trimmed = value.trim();
  if (trimmed === "" || trimmed.toLowerCase() === "unlimited") return null;
  const n = parseInt(trimmed, 10);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function formatLimitInput(limit: number | null): string {
  return limit === null ? "" : String(limit);
}

export function BudgetForm({ workspaceId }: BudgetFormProps) {
  const t = useTranslations("budgetSettings");
  const { data: budget, isLoading } = useBudget(workspaceId);
  const update = useUpdateBudget(workspaceId);

  const [dailyInput, setDailyInput] = useState("");
  const [monthlyInput, setMonthlyInput] = useState("");
  const [behavior, setBehavior] = useState<BudgetBehavior>("warn");
  const [dirty, setDirty] = useState(false);

  // Sync form state when server data loads.
  useEffect(() => {
    if (budget && !dirty) {
      setDailyInput(formatLimitInput(budget.daily_token_limit));
      setMonthlyInput(formatLimitInput(budget.monthly_token_limit));
      setBehavior(budget.behavior);
    }
  }, [budget, dirty]);

  function handleChange<T>(setter: (v: T) => void) {
    return (v: T) => {
      setter(v);
      setDirty(true);
    };
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    try {
      await update.mutateAsync({
        daily_token_limit: parseLimitInput(dailyInput),
        monthly_token_limit: parseLimitInput(monthlyInput),
        behavior,
      });
      setDirty(false);
      toast.success(t("saved"));
    } catch {
      toast.error(t("saveFailed"));
    }
  }

  if (isLoading) {
    return (
      <div className="text-sm text-muted-foreground animate-pulse">{t("loading")}</div>
    );
  }

  return (
    <form onSubmit={handleSave} className="space-y-6">
      {/* Current usage meters */}
      <div className="space-y-3">
        <h3 className="text-sm font-medium">{t("currentUsage")}</h3>
        <BudgetMeter
          label={t("daily")}
          used={budget?.daily_used ?? 0}
          limit={budget?.daily_token_limit ?? null}
          behavior={behavior}
        />
        <BudgetMeter
          label={t("monthly")}
          used={budget?.monthly_used ?? 0}
          limit={budget?.monthly_token_limit ?? null}
          behavior={behavior}
        />
      </div>

      {/* Limit inputs */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="daily-limit">{t("dailyLimit")}</Label>
          <Input
            id="daily-limit"
            placeholder={t("unlimited")}
            value={dailyInput}
            onChange={(e) => handleChange(setDailyInput)(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">{t("dailyLimitHint")}</p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="monthly-limit">{t("monthlyLimit")}</Label>
          <Input
            id="monthly-limit"
            placeholder={t("unlimited")}
            value={monthlyInput}
            onChange={(e) => handleChange(setMonthlyInput)(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">{t("monthlyLimitHint")}</p>
        </div>
      </div>

      {/* Behavior selector */}
      <div className="space-y-2">
        <Label>{t("behavior")}</Label>
        <div className="space-y-2">
          {BEHAVIOR_OPTIONS.map((opt) => (
            <label
              key={opt}
              className="flex items-start gap-3 cursor-pointer rounded-md border p-3 hover:bg-muted/50 transition-colors"
            >
              <input
                type="radio"
                name="behavior"
                value={opt}
                checked={behavior === opt}
                onChange={() => handleChange(setBehavior)(opt)}
                className="mt-0.5"
              />
              <div>
                <div className="text-sm font-medium">{t(`behavior_${opt}`)}</div>
                <div className="text-xs text-muted-foreground">
                  {t(`behavior_${opt}_description`)}
                </div>
              </div>
            </label>
          ))}
        </div>
      </div>

      <div className="flex justify-end">
        <Button type="submit" disabled={update.isPending || !dirty}>
          {update.isPending ? t("saving") : t("save")}
        </Button>
      </div>
    </form>
  );
}
