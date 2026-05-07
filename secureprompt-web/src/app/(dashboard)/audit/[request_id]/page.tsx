import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { AuditDetail } from "./audit-detail";

interface Params {
  request_id: string;
}

export default async function AuditDetailPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  const { request_id } = await params;

  return (
    <div className="space-y-6">
      <AuditDetail requestId={request_id} workspaceId={session.workspaceId} />
    </div>
  );
}
