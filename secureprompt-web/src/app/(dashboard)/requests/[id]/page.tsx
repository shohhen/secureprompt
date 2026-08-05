/**
 * Phase 5 / Plan 05-04 — Request detail page (RSC).
 *
 * Passes request_id + workspace_id down to a client component that uses
 * useRequestDetail(). The RSC layer only handles session + params routing.
 */

import { redirect } from "next/navigation";
import { getTranslations } from "next-intl/server";
import { getServerSession } from "@/lib/session";
import { RequestDetailView } from "./request-detail-view";

interface RequestDetailPageProps {
  params: Promise<{ id: string }>;
}

export default async function RequestDetailPage({
  params,
}: RequestDetailPageProps) {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  const { id } = await params;
  const t = await getTranslations("requestDetail");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("title")}</h1>
        <p className="text-sm text-muted-foreground mt-1 font-mono">{id}</p>
      </div>
      <RequestDetailView requestId={id} workspaceId={session.workspaceId} />
    </div>
  );
}
