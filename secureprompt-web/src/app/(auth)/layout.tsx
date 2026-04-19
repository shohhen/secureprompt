import type { ReactNode } from "react";

/**
 * Route-group layout for public /login (and future /forgot-password, /reset,
 * /accept-invite). Centers content in the viewport; does NOT require a
 * session — gating is handled by src/proxy.ts.
 */
export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <main className="min-h-dvh flex items-center justify-center bg-[var(--color-background)] text-[var(--color-foreground)] px-4 py-12">
      <div className="w-full max-w-sm">{children}</div>
    </main>
  );
}
