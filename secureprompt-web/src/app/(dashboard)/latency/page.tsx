/**
 * Phase 5 / Plan 05-03 — Latency percentiles analytics page (RSC).
 */

import { redirect } from "next/navigation";
import { getTranslations } from "next-intl/server";
import { getServerSession } from "@/lib/session";
import { LatencyChart } from "./latency-chart";
import type { MartName } from "@/lib/mart-exposures";

/** CI gate: check-mart-exposures.mjs reads this constant. */
export const MART_EXPOSURES: MartName[] = ["mart_latency_pctiles"];

export default async function LatencyPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");
  const t = await getTranslations("latency");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {t("description")}
        </p>
      </div>
      <LatencyChart workspaceId={session.workspaceId} />
    </div>
  );
}
