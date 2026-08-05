"use client";

/**
 * Phase 5 / Plan 05-05 — Dashboard top bar.
 *
 * Shows workspace badge, optional budget-exceeded banner, and sign-out button.
 * Listens for the `sp:budget-exceeded` custom event dispatched by api-fetch.ts
 * so the banner appears immediately when any API call returns 402.
 */

import { useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { signOut } from "next-auth/react";
import Link from "next/link";

interface TopbarProps {
  workspaceId: string;
}

export function Topbar({ workspaceId }: TopbarProps) {
  const t = useTranslations("topbar");
  const [budgetExceeded, setBudgetExceeded] = useState(false);

  useEffect(() => {
    const handler = () => setBudgetExceeded(true);
    window.addEventListener("sp:budget-exceeded", handler);
    return () => window.removeEventListener("sp:budget-exceeded", handler);
  }, []);

  return (
    <header className="flex flex-col border-b bg-card/50">
      <div className="flex h-14 items-center justify-between px-4">
        {/* i18n-exempt: product name, identical in every locale */}
        <span className="font-semibold text-sm">SecurePrompt</span>
        <div className="flex items-center gap-3">
          <span className="rounded bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">
            {/* i18n-exempt: "ws:" is an identifier prefix, not prose */}
            ws:{workspaceId.slice(0, 8)}
          </span>
          <button
            onClick={() => signOut({ callbackUrl: "/login" })}
            className="text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            {t("signOut")}
          </button>
        </div>
      </div>
      {budgetExceeded && (
        <div className="bg-destructive/10 border-t border-destructive/20 px-4 py-2 flex items-center justify-between">
          <p className="text-xs text-destructive font-medium">
            {t("budgetExceeded")}
          </p>
          <Link
            href="/settings/workspace"
            className="text-xs text-destructive underline underline-offset-2 hover:text-destructive/80"
            onClick={() => setBudgetExceeded(false)}
          >
            {t("manageBudget")}
          </Link>
        </div>
      )}
    </header>
  );
}
