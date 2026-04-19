/**
 * Phase 5 / Plan 05-03 — Policy violations analytics page (RSC).
 */

import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { PolicyChart } from "./policy-chart";
import type { MartName } from "@/lib/mart-exposures";

/** CI gate: check-mart-exposures.mjs reads this constant. */
export const MART_EXPOSURES: MartName[] = ["mart_policy_violations"];

export default async function PolicyPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Policy Violations</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Enforced and dry-run policy violation counts by rule.
        </p>
      </div>
      <PolicyChart workspaceId={session.workspaceId} />
    </div>
  );
}
