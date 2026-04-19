/**
 * Phase 5 / Plan 05-04 — Policy Rules settings page (RSC shell).
 */

import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { PolicyRulesPanel } from "./policy-rules-panel";

export default async function PolicyRulesPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return <PolicyRulesPanel />;
}
