"use client";

/**
 * Phase 5 / Plan 05-05 — Workspace Budget Form
 *
 * Inline editable form that fetches the current budget settings and allows
 * an admin to update daily/monthly token limits and the enforcement behavior.
 * A viewer can read the current usage but cannot save.
 */

import { useState, useEffect } from "react";
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

const BEHAVIOR_OPTIONS: { value: BudgetBehavior; label: string; description: string }[] = [
  {
    value: "block",
    label: "Block",
    description: "Return HTTP 402 when the limit is exceeded.",
  },
  {
    value: "warn",
    label: "Warn",
    description: "Allow through but add X-SecurePrompt-Budget-Warning header.",
  },
  {
    value: "flag",
    label: "Flag",
    description: "Allow through silently; flag in analytics only.",
  },
];

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
      toast.success("Budget settings saved.");
    } catch {
      toast.error("Failed to save budget settings.");
    }
  }

  if (isLoading) {
    return (
      <div className="text-sm text-muted-foreground animate-pulse">Loading budget…</div>
    );
  }

  return (
    <form onSubmit={handleSave} className="space-y-6">
      {/* Current usage meters */}
      <div className="space-y-3">
        <h3 className="text-sm font-medium">Current Usage</h3>
        <BudgetMeter
          label="Daily"
          used={budget?.daily_used ?? 0}
          limit={budget?.daily_token_limit ?? null}
          behavior={behavior}
        />
        <BudgetMeter
          label="Monthly"
          used={budget?.monthly_used ?? 0}
          limit={budget?.monthly_token_limit ?? null}
          behavior={behavior}
        />
      </div>

      {/* Limit inputs */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="daily-limit">Daily token limit</Label>
          <Input
            id="daily-limit"
            placeholder="Unlimited"
            value={dailyInput}
            onChange={(e) => handleChange(setDailyInput)(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">Leave blank for no daily limit.</p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="monthly-limit">Monthly token limit</Label>
          <Input
            id="monthly-limit"
            placeholder="Unlimited"
            value={monthlyInput}
            onChange={(e) => handleChange(setMonthlyInput)(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">Leave blank for no monthly limit.</p>
        </div>
      </div>

      {/* Behavior selector */}
      <div className="space-y-2">
        <Label>Enforcement behavior</Label>
        <div className="space-y-2">
          {BEHAVIOR_OPTIONS.map((opt) => (
            <label
              key={opt.value}
              className="flex items-start gap-3 cursor-pointer rounded-md border p-3 hover:bg-muted/50 transition-colors"
            >
              <input
                type="radio"
                name="behavior"
                value={opt.value}
                checked={behavior === opt.value}
                onChange={() => handleChange(setBehavior)(opt.value)}
                className="mt-0.5"
              />
              <div>
                <div className="text-sm font-medium">{opt.label}</div>
                <div className="text-xs text-muted-foreground">{opt.description}</div>
              </div>
            </label>
          ))}
        </div>
      </div>

      <div className="flex justify-end">
        <Button type="submit" disabled={update.isPending || !dirty}>
          {update.isPending ? "Saving…" : "Save budget settings"}
        </Button>
      </div>
    </form>
  );
}
