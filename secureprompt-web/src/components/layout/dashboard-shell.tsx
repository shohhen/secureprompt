"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { NuqsAdapter } from "nuqs/adapters/next/app";
import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { PageSkeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

interface DashboardShellProps {
  children: React.ReactNode;
  workspaceId: string;
}

export function DashboardShell({ children, workspaceId }: DashboardShellProps) {
  const pathname = usePathname();
  const [desktopCollapsed, setDesktopCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

  const handleSidebarToggle = useCallback(() => {
    if (window.matchMedia("(min-width: 768px)").matches) {
      setDesktopCollapsed((p) => !p);
    } else {
      setMobileOpen((p) => !p);
    }
  }, []);

  return (
    <NuqsAdapter>
      <div className="h-screen overflow-hidden bg-sidebar">
        <aside
          className={cn(
            "fixed inset-y-0 left-0 z-30 w-64 p-2 transition-[transform,opacity,width] duration-300 ease-out will-change-[transform,width]",
            mobileOpen
              ? "translate-x-0 opacity-100 pointer-events-auto"
              : "-translate-x-full opacity-0 pointer-events-none",
            "md:translate-x-0 md:opacity-100 md:pointer-events-auto",
            desktopCollapsed ? "md:w-[4.5rem]" : "md:w-64"
          )}
        >
          <Sidebar collapsed={desktopCollapsed} />
        </aside>

        {mobileOpen && (
          <button
            type="button"
            aria-label="Close sidebar"
            className="fixed inset-0 z-20 bg-black/45 md:hidden"
            onClick={() => setMobileOpen(false)}
          />
        )}

        <div
          className={cn(
            "h-screen transition-[padding-left] duration-300",
            desktopCollapsed ? "md:pl-[4.5rem]" : "md:pl-64"
          )}
        >
          <div className="flex h-screen flex-col overflow-hidden md:m-2 md:h-[calc(100vh-1rem)] md:rounded-xl md:border md:border-border/80 md:bg-background md:shadow-sm">
            <Header onToggleSidebar={handleSidebarToggle} workspaceId={workspaceId} />
            <main className="flex-1 overflow-hidden">
              <div className="h-full overflow-y-auto p-4 md:p-6 lg:p-8">
                <Suspense fallback={<PageSkeleton />}>{children}</Suspense>
              </div>
            </main>
          </div>
        </div>
      </div>
    </NuqsAdapter>
  );
}
