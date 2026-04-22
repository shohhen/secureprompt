import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { AuditTable } from "./audit-table";

export default async function AuditPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Audit Log</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Recent requests that triggered policy violations.
        </p>
      </div>
      <AuditTable workspaceId={session.workspaceId} />
    </div>
  );
}
