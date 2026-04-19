/**
 * Phase 5 / Plan 05-04 — Settings section layout with nav tabs.
 */

import Link from "next/link";
import type { ReactNode } from "react";

const NAV_ITEMS = [
  { href: "/settings/keys", label: "API Keys" },
  { href: "/settings/providers", label: "Providers" },
  { href: "/settings/policy-rules", label: "Policy Rules" },
  { href: "/settings/workspace", label: "Workspace" },
];

export default function SettingsLayout({ children }: { children: ReactNode }) {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Manage API keys, AI providers, and policy enforcement rules.
        </p>
      </div>

      {/* Tab nav */}
      <nav className="flex gap-1 border-b">
        {NAV_ITEMS.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-muted/50 rounded-t-md transition-colors"
          >
            {item.label}
          </Link>
        ))}
      </nav>

      <div>{children}</div>
    </div>
  );
}
