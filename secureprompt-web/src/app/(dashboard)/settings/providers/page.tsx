/**
 * Phase 5 / Plan 05-04 — Providers settings page (RSC shell).
 */

import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { ProvidersPanel } from "./providers-panel";

export default async function ProvidersPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return <ProvidersPanel />;
}
