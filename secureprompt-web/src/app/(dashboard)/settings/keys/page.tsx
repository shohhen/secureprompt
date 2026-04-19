/**
 * Phase 5 / Plan 05-04 — API Keys settings page (RSC shell).
 */

import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { KeysPanel } from "./keys-panel";

export default async function KeysPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return <KeysPanel workspaceId={session.workspaceId} />;
}
