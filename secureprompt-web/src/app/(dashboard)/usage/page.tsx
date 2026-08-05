/**
 * Phase 5 / Plan 05-03 — Usage analytics page (RSC).
 *
 * Server reads the session (auth gate + workspaceId extraction) then passes
 * workspaceId to the "use client" chart component.
 */

import { redirect } from "next/navigation";
import { getTranslations } from "next-intl/server";
import { getServerSession } from "@/lib/session";
import { UsageChart } from "./usage-chart";
import type { MartName } from "@/lib/mart-exposures";

/** CI gate: check-mart-exposures.mjs reads this constant. */
export const MART_EXPOSURES: MartName[] = ["mart_usage_daily"];

export default async function UsagePage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");
  const t = await getTranslations("usage");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {t("description")}
        </p>
      </div>
      <UsageChart workspaceId={session.workspaceId} />
    </div>
  );
}
