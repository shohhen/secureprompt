"use client";

/**
 * Phase 5 / Plan 05-03 — Dashboard top bar.
 *
 * Shows workspace badge and sign-out button. `workspaceId` is passed as a
 * prop (resolved in the RSC layout from the server session).
 */

import { signOut } from "next-auth/react";

interface TopbarProps {
  workspaceId: string;
}

export function Topbar({ workspaceId }: TopbarProps) {
  return (
    <header className="flex h-14 items-center justify-between border-b bg-card/50 px-4">
      <span className="font-semibold text-sm">SecurePrompt</span>
      <div className="flex items-center gap-3">
        <span className="rounded bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">
          ws:{workspaceId.slice(0, 8)}
        </span>
        <button
          onClick={() => signOut({ callbackUrl: "/login" })}
          className="text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          Sign out
        </button>
      </div>
    </header>
  );
}
