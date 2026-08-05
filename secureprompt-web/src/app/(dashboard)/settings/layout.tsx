/**
 * Phase 5 / Plan 05-04 — Settings section layout with nav tabs.
 */

import Link from "next/link";
import { getTranslations } from "next-intl/server";
import type { ReactNode } from "react";

/** `key` indexes the `settingsNav` namespace. */
const NAV_ITEMS = [
  { href: "/settings/keys", key: "keys" },
  { href: "/settings/providers", key: "providers" },
  { href: "/settings/policy-rules", key: "policyRules" },
  { href: "/settings/workspace", key: "workspace" },
  { href: "/settings/members", key: "members" },
  { href: "/settings/security", key: "security" },
  { href: "/settings/license", key: "license" },
] as const;

export default async function SettingsLayout({ children }: { children: ReactNode }) {
  const t = await getTranslations("settings");
  const tNav = await getTranslations("settingsNav");
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {t("description")}
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
            {tNav(item.key)}
          </Link>
        ))}
      </nav>

      <div>{children}</div>
    </div>
  );
}
