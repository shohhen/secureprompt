"use client";

import type { ReactNode } from "react";
import { SessionProvider } from "next-auth/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/sonner";
import { getQueryClient } from "@/lib/query-client";

/**
 * Client-side providers that wrap the app. Mounted from the root layout.
 * Order matters: SessionProvider outside (so components can read useSession),
 * QueryClientProvider inside (hydration-friendly).
 */
export function Providers({ children }: { children: ReactNode }) {
  const queryClient = getQueryClient();
  return (
    <SessionProvider>
      <QueryClientProvider client={queryClient}>
        {children}
        <Toaster />
      </QueryClientProvider>
    </SessionProvider>
  );
}
