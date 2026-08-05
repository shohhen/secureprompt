/**
 * WS6-3 — what happens when a message is missing.
 *
 * A silent fallback is the thing to avoid: if `ru` quietly renders the English
 * source, a half-translated console ships looking finished and nobody finds
 * out until an auditor reads it. So outside production a missing message is a
 * thrown error, which turns it into a failing test or a red dev overlay.
 *
 * In production it is downgraded to a log plus the key path, because a bank's
 * console must not white-screen over a copy defect.
 */
import { IntlError, IntlErrorCode } from "next-intl";

export function onIntlError(error: IntlError): void {
  if (process.env.NODE_ENV === "production") {
    // Surfaces in the container log; the render continues with the key path.
    console.error(`[i18n] ${error.code}: ${error.message}`);
    return;
  }
  throw error;
}

/**
 * Rendered in place of a missing message in production. The dotted key path is
 * deliberately un-pretty: it is obviously a defect rather than a plausible
 * English sentence sitting inside a Russian page.
 */
export function getMessageFallback({
  namespace,
  key,
  error,
}: {
  namespace?: string;
  key: string;
  error: IntlError;
}): string {
  const path = [namespace, key].filter(Boolean).join(".");
  if (error.code === IntlErrorCode.MISSING_MESSAGE) return path;
  return `${path} (${error.code})`;
}
