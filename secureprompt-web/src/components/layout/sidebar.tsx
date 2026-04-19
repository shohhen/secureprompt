"use client";

/**
 * Phase 5 / Plan 05-03 — Dashboard sidebar navigation.
 *
 * Links to the four analytics pages. Active state is derived from the current
 * pathname via `usePathname`.
 */

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { href: "/usage", label: "Usage" },
  { href: "/cost", label: "Cost by Model" },
  { href: "/policy", label: "Policy Violations" },
  { href: "/latency", label: "Latency" },
] as const;

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-56 shrink-0 border-r bg-card/50 flex flex-col gap-1 p-3">
      <p className="mb-2 px-2 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
        Analytics
      </p>
      {NAV_ITEMS.map((item) => (
        <Link
          key={item.href}
          href={item.href}
          className={cn(
            "rounded-md px-3 py-2 text-sm font-medium transition-colors",
            pathname.startsWith(item.href)
              ? "bg-primary/10 text-primary"
              : "text-foreground/70 hover:bg-accent hover:text-foreground"
          )}
        >
          {item.label}
        </Link>
      ))}
    </aside>
  );
}
