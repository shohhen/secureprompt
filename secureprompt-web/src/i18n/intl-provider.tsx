"use client";

/**
 * WS6-3 — the client half of the i18n layer.
 *
 * `onError` and `getMessageFallback` are functions, so a Server Component
 * cannot pass them across the RSC boundary. This wrapper is a Client Component
 * purely so those two live on the client side of the boundary while `locale`
 * and `messages` cross it as plain serialisable data.
 */
import { NextIntlClientProvider } from "next-intl";
import type { ReactNode } from "react";
import type { Locale } from "./config";
import { getMessageFallback, onIntlError } from "./error-policy";

export function IntlProvider({
  locale,
  messages,
  timeZone,
  children,
}: {
  locale: Locale;
  messages: Record<string, unknown>;
  timeZone: string;
  children: ReactNode;
}) {
  return (
    <NextIntlClientProvider
      locale={locale}
      messages={messages}
      timeZone={timeZone}
      onError={onIntlError}
      getMessageFallback={getMessageFallback}
    >
      {children}
    </NextIntlClientProvider>
  );
}
