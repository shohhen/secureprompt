/**
 * Phase 5 / Plan 05-03 — Policy violations analytics page (RSC).
 */

import { redirect } from "next/navigation";
import { getTranslations } from "next-intl/server";
import { getServerSession } from "@/lib/session";
import { PolicyChart } from "./policy-chart";
import type { MartName } from "@/lib/mart-exposures";

/** CI gate: check-mart-exposures.mjs reads this constant. */
export const MART_EXPOSURES: MartName[] = ["mart_policy_violations"];

export default async function PolicyPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");
  const t = await getTranslations("policy");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {t("description")}
        </p>
      </div>
      <PolicyChart workspaceId={session.workspaceId} />
    </div>
  );
}
