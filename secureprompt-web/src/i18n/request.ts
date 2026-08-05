/**
 * WS6-3 — per-request i18n configuration for the App Router.
 *
 * There is no `[locale]` route segment and no locale prefix in any URL. The
 * locale is a stored operator preference, resolved here on the server, so:
 *
 *   - Server Components translate during the RSC render and ship no message
 *     bundle to the browser at all;
 *   - Client Components read the same request's messages out of the provider
 *     mounted in the root layout, so exactly one locale is ever sent;
 *   - Next.js 16 allows a single `src/proxy.ts`, which already owns the auth
 *     redirect and the nonce CSP. Locale routing would have to be merged into
 *     it, and every `href`, `callbackUrl` and `typedRoutes` literal in the
 *     console would need a prefix, for a surface that is auth-gated and never
 *     indexed. Cookie negotiation buys the same behaviour for none of that.
 */
import { getRequestConfig } from "next-intl/server";
import { cookies, headers } from "next/headers";
import { LOCALE_COOKIE, negotiateLocale } from "./config";
import { getMessageFallback, onIntlError } from "./error-policy";

export default getRequestConfig(async () => {
  const [cookieStore, headerList] = await Promise.all([cookies(), headers()]);

  const locale = negotiateLocale(
    cookieStore.get(LOCALE_COOKIE)?.value,
    headerList.get("accept-language"),
  );

  const messages = (await import(`./messages/${locale}.json`)).default;

  return {
    locale,
    messages,
    onError: onIntlError,
    getMessageFallback,
    // Pinned so server and client render the same wall-clock text. The market
    // this ships to is UTC+5; override per deployment if that changes.
    timeZone: process.env.SP_CONSOLE_TIMEZONE ?? "Asia/Tashkent",
  };
});
