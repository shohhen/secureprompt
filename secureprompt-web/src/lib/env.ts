import { z } from "zod";

/**
 * Server-side environment validation.
 * Fails fast at import time if a required variable is missing — prevents
 * the dev footgun where an empty NEXTAUTH_SECRET silently degrades security.
 */
const serverSchema = z.object({
  NEXTAUTH_SECRET: z.string().min(16, "NEXTAUTH_SECRET must be at least 16 chars"),
  NEXTAUTH_URL: z.string().url(),
  NEXT_PUBLIC_API_URL: z.string().url(),
});

const clientSchema = z.object({
  NEXT_PUBLIC_API_URL: z.string().url(),
});

type ServerEnv = z.infer<typeof serverSchema>;
type ClientEnv = z.infer<typeof clientSchema>;

function parseEnv(): ServerEnv | ClientEnv {
  // `typeof window` check: on the client we only need NEXT_PUBLIC_* vars.
  // NEXTAUTH_SECRET MUST NEVER be inlined into the browser bundle.
  if (typeof window === "undefined") {
    const parsed = serverSchema.safeParse(process.env);
    if (!parsed.success) {
      const errors = parsed.error.flatten().fieldErrors;
      throw new Error(
        `Invalid server environment:\n${JSON.stringify(errors, null, 2)}`,
      );
    }
    return parsed.data;
  }
  const parsed = clientSchema.safeParse({
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL,
  });
  if (!parsed.success) {
    const errors = parsed.error.flatten().fieldErrors;
    throw new Error(
      `Invalid client environment:\n${JSON.stringify(errors, null, 2)}`,
    );
  }
  return parsed.data;
}

export const env = parseEnv() as ServerEnv;

/** Public (bundle-safe) subset for client use. */
export const publicEnv = {
  NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080",
} as const;
