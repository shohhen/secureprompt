/**
 * NextAuth v5 route handler — catches all /api/auth/* requests.
 * `handlers` is produced by `NextAuth(authConfig)` in `src/lib/auth.ts`.
 */
import { handlers } from "@/lib/auth";

export const { GET, POST } = handlers;
