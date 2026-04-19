/**
 * Thin server-only wrapper around `auth()` — returns the typed SessionShape
 * (or null) for use in Server Components, Route Handlers, and middleware.
 *
 * Do NOT import this from a Client Component — use useSession() from
 * next-auth/react instead.
 */
import "server-only";
import { auth } from "@/lib/auth";
import type { AppSessionShape } from "@/types/next-auth";

export async function getServerSession(): Promise<AppSessionShape | null> {
  const session = await auth();
  if (!session) return null;
  return session as unknown as AppSessionShape;
}
