/**
 * Phase 5 / Plan 05-04 — Requests list page (RSC).
 *
 * Server component: reads session, renders filter bar + <RequestsTable />.
 * URL state (from/to/model/has_violation) is managed by nuqs in the client
 * child — the RSC only passes the workspaceId.
 */

import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { RequestsTable } from "./requests-table";
import { DateRangeFilter } from "@/components/filters/date-range-filter";

export default async function RequestsPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Requests</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Audit trail of all LLM requests proxied through SecurePrompt.
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-4">
        <DateRangeFilter />
      </div>
      <RequestsTable workspaceId={session.workspaceId} />
    </div>
  );
}
