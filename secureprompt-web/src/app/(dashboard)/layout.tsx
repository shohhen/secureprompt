import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { DashboardShell } from "@/components/layout/dashboard-shell";
import type { ReactNode } from "react";

export default async function DashboardLayout({ children }: { children: ReactNode }) {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <DashboardShell workspaceId={session.workspaceId}>
      {children}
    </DashboardShell>
  );
}
