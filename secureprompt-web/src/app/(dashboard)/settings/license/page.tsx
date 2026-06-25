/**
 * Settings → License page (RSC shell).
 *
 * Admin-gated: the gateway's /v1/license routes require an admin token;
 * we gate the page itself to avoid showing a broken UI to viewers.
 */

import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { LicenseClient } from "./license-client";

export default async function LicensePage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return <LicenseClient />;
}
