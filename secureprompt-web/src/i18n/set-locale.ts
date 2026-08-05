"use server";

/**
 * WS6-3 — persist the operator's locale choice.
 *
 * A Server Action rather than an API route: the cookie has to be set on the
 * server anyway, and the subsequent `revalidatePath("/", "layout")` re-renders
 * the Server Components with the new locale without a full page load.
 */
import { revalidatePath } from "next/cache";
import { cookies } from "next/headers";
import { LOCALE_COOKIE, LOCALE_COOKIE_MAX_AGE, isLocale, type Locale } from "./config";

export async function setLocale(next: Locale): Promise<void> {
  if (!isLocale(next)) {
    // Never write an unvalidated value into the cookie that drives a dynamic
    // `import(./messages/${locale}.json)` on every request.
    throw new Error(`Unsupported locale: ${String(next)}`);
  }

  const store = await cookies();
  store.set(LOCALE_COOKIE, next, {
    path: "/",
    maxAge: LOCALE_COOKIE_MAX_AGE,
    sameSite: "lax",
    httpOnly: false,
  });

  revalidatePath("/", "layout");
}
