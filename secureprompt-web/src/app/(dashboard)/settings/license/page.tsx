/**
 * Settings → License page (RSC shell).
 *
 * Admin-gated: the gateway's /v1/license routes require an admin token;
 * we gate the page itself to avoid showing a broken UI to viewers.
 */

import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { canWrite } from "@/lib/roles";
import { LicenseClient } from "./license-client";

export default async function LicensePage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");
  // /v1/license (GET included) is admin-gated on the gateway, so a
  // non-admin would only ever see a 403. Gate the route here instead of
  // rendering a broken page. Mirrors the gateway's owner/admin RBAC.
  if (!canWrite(session.role)) redirect("/settings");

  return <LicenseClient />;
}
