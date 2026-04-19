"use client";

import { useEffect, type ReactNode } from "react";
import { SessionProvider } from "next-auth/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { toast, Toaster } from "sonner";
import { getQueryClient } from "@/lib/query-client";

/**
 * Client-side providers that wrap the app. Mounted from the root layout.
 * Order matters: SessionProvider outside (so components can read useSession),
 * QueryClientProvider inside (hydration-friendly).
 *
 * Phase 5 / Plan 05-05 — Listens for the `sp:budget-exceeded` custom event
 * dispatched by `api-fetch.ts` on 402 responses, and shows a toast so any
 * page that triggers a budget-exceeded response shows the user a clear message.
 */

function BudgetExceededListener() {
  useEffect(() => {
    const handler = () => {
      toast.error(
        "Budget exceeded. Requests are being blocked. Contact an admin.",
      );
    };
    window.addEventListener("sp:budget-exceeded", handler);
    return () => window.removeEventListener("sp:budget-exceeded", handler);
  }, []);
  return null;
}

export function Providers({ children }: { children: ReactNode }) {
  const queryClient = getQueryClient();
  return (
    <SessionProvider>
      <QueryClientProvider client={queryClient}>
        <BudgetExceededListener />
        {children}
        <Toaster />
      </QueryClientProvider>
    </SessionProvider>
  );
}
