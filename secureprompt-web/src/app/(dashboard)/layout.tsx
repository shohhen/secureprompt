/**
 * Phase 5 / Plan 05-03 — Auth-gated RSC layout for all dashboard pages.
 *
 * Reads the server session via `getServerSession()` and redirects to /login if
 * there is no active session (belt-and-suspenders: middleware in proxy.ts
 * already gates the route group, but RSC re-check prevents cache misses from
 * exposing the shell to unauthenticated users).
 */

import { redirect } from "next/navigation";
import { NuqsAdapter } from "nuqs/adapters/next/app";
import { getServerSession } from "@/lib/session";
import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";
import type { ReactNode } from "react";

export default async function DashboardLayout({
  children,
}: {
  children: ReactNode;
}) {
  const session = await getServerSession();
  if (!session) {
    redirect("/login?reason=unauthenticated");
  }

  return (
    <NuqsAdapter>
      <div className="flex h-dvh flex-col overflow-hidden">
        <Topbar workspaceId={session.workspaceId} />
        <div className="flex flex-1 overflow-hidden">
          <Sidebar />
          <main className="flex-1 overflow-y-auto p-6">{children}</main>
        </div>
      </div>
    </NuqsAdapter>
  );
}
