"use client";

/**
 * Phase 5 / Plan 05-04 — Detection chips drawer for request detail.
 *
 * IMPORTANT: Detection class labels are rendered as React text nodes inside
 * <mark> elements — never via dangerouslySetInnerHTML.
 */

import type { PolicyEventSummary } from "@/lib/hooks/use-requests";
import { useTranslations } from "next-intl";

interface DetectionsDrawerProps {
  events: PolicyEventSummary[];
}

const ACTION_COLORS: Record<string, string> = {
  deny: "bg-red-100 text-red-800 border-red-300",
  allow: "bg-green-100 text-green-800 border-green-300",
  redact: "bg-yellow-100 text-yellow-800 border-yellow-300",
  transform: "bg-blue-100 text-blue-800 border-blue-300",
  flag: "bg-orange-100 text-orange-800 border-orange-300",
};

function DetectionChip({ event }: { event: PolicyEventSummary }) {
  const t = useTranslations("requestDetail");
  const colorClass =
    ACTION_COLORS[event.action] ?? "bg-muted text-muted-foreground border-border";

  return (
    <mark
      data-action={event.action}
      data-dry-run={event.dry_run ? "true" : "false"}
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-xs font-medium not-italic ${colorClass}`}
    >
      {/* Rule name — plain React text node, no innerHTML */}
      {event.rule_name}
      {event.dry_run && (
        <span className="opacity-60">{t("dryRunChip")}</span>
      )}
    </mark>
  );
}

export function DetectionsDrawer({ events }: DetectionsDrawerProps) {
  const t = useTranslations("requestDetail");
  if (events.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        {t("noPolicyEvents")}
      </p>
    );
  }

  return (
    <div className="space-y-2">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
        {t("policyEvents")}
      </p>
      <div className="flex flex-wrap gap-2">
        {events.map((ev) => (
          <DetectionChip key={ev.rule_id} event={ev} />
        ))}
      </div>
    </div>
  );
}
