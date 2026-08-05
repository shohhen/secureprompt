"use client";

/**
 * Phase 5 / Plan 05-03 — Date range filter component.
 *
 * Uses nuqs for URL state so filters survive page refresh and can be bookmarked.
 * The parent page reads `from` / `to` from the URL via `useQueryState`.
 */

import { useQueryState } from "nuqs";
import { useTranslations } from "next-intl";
import { format, subDays } from "date-fns";

const FORMAT = "yyyy-MM-dd";

function today(): string {
  return format(new Date(), FORMAT);
}

function daysAgo(n: number): string {
  return format(subDays(new Date(), n), FORMAT);
}

export function DateRangeFilter() {
  const t = useTranslations("filters");
  const [from, setFrom] = useQueryState("from", { defaultValue: daysAgo(7) });
  const [to, setTo] = useQueryState("to", { defaultValue: today() });

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <label className="text-sm font-medium text-foreground/80">{t("from")}</label>
      <input
        type="date"
        value={from}
        max={to}
        onChange={(e) => setFrom(e.target.value)}
        className="border rounded px-2 py-1 text-sm bg-background"
      />
      <label className="text-sm font-medium text-foreground/80">{t("to")}</label>
      <input
        type="date"
        value={to}
        min={from}
        max={today()}
        onChange={(e) => setTo(e.target.value)}
        className="border rounded px-2 py-1 text-sm bg-background"
      />
    </div>
  );
}
