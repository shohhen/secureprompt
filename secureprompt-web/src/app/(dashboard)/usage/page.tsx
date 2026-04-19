/**
 * Phase 5 / Plan 05-03 — Usage analytics page (RSC).
 *
 * Server reads the session (auth gate + workspaceId extraction) then passes
 * workspaceId to the "use client" chart component.
 */

import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { UsageChart } from "./usage-chart";
import type { MartName } from "@/lib/mart-exposures";

/** CI gate: check-mart-exposures.mjs reads this constant. */
export const MART_EXPOSURES: MartName[] = ["mart_usage_daily"];

export default async function UsagePage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Token Usage</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Daily token consumption and request volume per model.
        </p>
      </div>
      <UsageChart workspaceId={session.workspaceId} />
    </div>
  );
}
