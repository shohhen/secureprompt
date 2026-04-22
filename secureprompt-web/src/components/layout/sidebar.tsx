"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";
import {
  BarChart3,
  ChevronRight,
  DollarSign,
  FileText,
  Gauge,
  Key,
  Search,
  Database,
  Shield,
  ShieldCheck,
  ClipboardList,
  Server,
  Timer,
  Settings,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { name: "Usage", href: "/usage", icon: BarChart3 },
  { name: "Cost by Model", href: "/cost", icon: DollarSign },
  { name: "Latency", href: "/latency", icon: Timer },
  { name: "Audit Log", href: "/audit", icon: ClipboardList },
  { name: "Secure Mode", href: "/secure-mode", icon: Shield },
  { name: "File Scan", href: "/file-scan", icon: Search },
  { name: "Semantic Search", href: "/semantic-search", icon: Database },
  { name: "Policy Violations", href: "/policy", icon: FileText },
  { name: "Providers", href: "/providers", icon: Server },
  { name: "API Keys", href: "/api-keys", icon: Key },
  { name: "Settings", href: "/settings", icon: Settings },
] as const;

const PRIMARY_COUNT = 4;

export function Sidebar({ collapsed = false }: { collapsed?: boolean }) {
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    for (const item of NAV_ITEMS) {
      if (!pathname.startsWith(item.href)) router.prefetch(item.href);
    }
  }, [pathname, router]);

  const primary = NAV_ITEMS.slice(0, PRIMARY_COUNT);
  const security = NAV_ITEMS.slice(PRIMARY_COUNT);

  return (
    <div className="flex h-full w-full flex-col rounded-xl border border-sidebar-border bg-sidebar text-sidebar-foreground shadow-sm">
      {/* Logo */}
      <div className={cn("border-b border-sidebar-border transition-all duration-300", collapsed ? "p-2" : "p-3")}>
        <div className={cn("flex items-center", collapsed ? "justify-center" : "gap-2")}>
          <Link
            href="/usage"
            className={cn(
              "group flex items-center rounded-md transition-colors hover:bg-sidebar-accent",
              collapsed ? "justify-center p-1.5" : "gap-2 px-1 py-1.5"
            )}
          >
            <span className="flex size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground">
              <ShieldCheck className="size-4" />
            </span>
            <span
              className={cn(
                "overflow-hidden transition-[max-width,opacity,transform] duration-200",
                collapsed ? "max-w-0 -translate-x-1 opacity-0" : "max-w-[10rem] translate-x-0 opacity-100"
              )}
            >
              <span className="block text-sm font-semibold leading-tight">SecurePrompt</span>
              <span className="block text-[11px] text-sidebar-foreground/70">Security control plane</span>
            </span>
          </Link>
        </div>
      </div>

      {/* Nav */}
      <div className={cn("flex-1 overflow-y-auto p-2", collapsed && "px-1")}>
        <NavGroup label="Analytics" items={primary} pathname={pathname} collapsed={collapsed} />
        <NavGroup label="Security & Config" items={security} pathname={pathname} collapsed={collapsed} />

        {collapsed ? (
          <div className="mt-3 flex justify-center py-2">
            <span className="size-2 rounded-full bg-emerald-400 ring-2 ring-emerald-400/25" />
          </div>
        ) : (
          <div className="mt-3 rounded-lg border border-sidebar-border bg-background/60 p-3">
            <div className="flex items-center gap-2 text-sm font-medium">
              <Gauge className="size-4 text-sidebar-foreground/80" />
              Runtime Status
            </div>
            <p className="mt-1 text-xs text-sidebar-foreground/70">All controls active and monitoring.</p>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="border-t border-sidebar-border p-2">
        {collapsed ? (
          <div className="flex justify-center">
            <Badge variant="outline" className="border-sidebar-border bg-background/70 px-1.5 text-[10px] text-sidebar-foreground">
              v1
            </Badge>
          </div>
        ) : (
          <div className="flex items-center justify-between rounded-lg px-2 py-1.5">
            <span className="text-xs text-sidebar-foreground/70">System</span>
            <Badge variant="outline" className="border-sidebar-border bg-background/70 text-sidebar-foreground">
              v1.0
            </Badge>
          </div>
        )}
      </div>
    </div>
  );
}

function NavGroup({
  label,
  items,
  pathname,
  collapsed,
}: {
  label: string;
  items: readonly { name: string; href: string; icon: React.ComponentType<{ className?: string }> }[];
  pathname: string;
  collapsed: boolean;
}) {
  return (
    <section className="mb-2">
      {!collapsed && (
        <p className="px-2 py-2 text-xs font-medium text-sidebar-foreground/70">{label}</p>
      )}
      <nav className="space-y-0.5">
        {items.map((item) => {
          const isActive = pathname.startsWith(item.href);
          return (
            <Link
              key={item.name}
              href={item.href}
              title={item.name}
              className={cn(
                "group flex h-8 items-center rounded-md text-sm transition-colors",
                collapsed ? "justify-center px-0" : "gap-2 px-2",
                isActive
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-sidebar-foreground/90 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              )}
            >
              <item.icon className="size-4 shrink-0" />
              <span
                className={cn(
                  "truncate transition-[max-width,opacity,transform] duration-200",
                  collapsed ? "max-w-0 -translate-x-1 opacity-0" : "max-w-[10.5rem] translate-x-0 opacity-100"
                )}
              >
                {item.name}
              </span>
              <ChevronRight
                className={cn(
                  "ml-auto size-3.5 opacity-0 transition-opacity",
                  collapsed ? "hidden" : "group-hover:opacity-40",
                  isActive && !collapsed && "opacity-40"
                )}
              />
            </Link>
          );
        })}
      </nav>
    </section>
  );
}
