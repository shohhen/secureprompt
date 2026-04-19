/**
 * Phase 5 / Plan 05-03 — Cost by model analytics page (RSC).
 */

import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { CostChart } from "./cost-chart";
import type { MartName } from "@/lib/mart-exposures";

/** CI gate: check-mart-exposures.mjs reads this constant. */
export const MART_EXPOSURES: MartName[] = ["mart_cost_by_model"];

export default async function CostPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Cost by Model</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Daily and rolling 7-day cost breakdown by AI model.
        </p>
      </div>
      <CostChart workspaceId={session.workspaceId} />
    </div>
  );
}
