/**
 * Phase 5 / Plan 05-05 — Workspace settings page (RSC shell).
 *
 * Hosts the budget configuration form. Passes workspaceId from the server
 * session so the client form can call /v1/workspaces/{id}/budgets.
 */

import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { BudgetForm } from "./budget-form";

export default async function WorkspaceSettingsPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h2 className="text-lg font-medium">Workspace Budget</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Set daily and monthly token limits for this workspace. Limits are
          enforced at the gateway level before requests reach AI providers.
        </p>
      </div>
      <BudgetForm workspaceId={session.workspaceId} />
    </div>
  );
}
