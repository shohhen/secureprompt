/**
 * WS6-3 — render helper that supplies the real i18n context.
 *
 * Component tests mount Client Components directly, so nothing provides the
 * context that `src/app/layout.tsx` mounts in the running app. This wraps them
 * in a genuine `NextIntlClientProvider` loaded with the shipped `en.json` —
 * not a stub — so assertions still read the real English copy and a broken
 * message key still fails the test through `onIntlError`.
 */
import type { ReactElement, ReactNode } from "react";
import { render, type RenderOptions, type RenderResult } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import messages from "@/i18n/messages/en.json";
import { getMessageFallback, onIntlError } from "@/i18n/error-policy";

export function IntlWrapper({ children }: { children: ReactNode }) {
  return (
    <NextIntlClientProvider
      locale="en"
      messages={messages}
      timeZone="Asia/Tashkent"
      onError={onIntlError}
      getMessageFallback={getMessageFallback}
    >
      {children}
    </NextIntlClientProvider>
  );
}

/** Drop-in replacement for `@testing-library/react`'s `render`. */
export function renderWithIntl(
  ui: ReactElement,
  options?: Omit<RenderOptions, "wrapper">,
): RenderResult {
  return render(ui, { wrapper: IntlWrapper, ...options });
}
