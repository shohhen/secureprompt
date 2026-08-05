import type { Metadata } from "next";
import type { ReactNode } from "react";
import { headers } from "next/headers";
import { getLocale, getMessages, getTranslations } from "next-intl/server";
import { Providers } from "@/components/providers";
import { htmlLang, type Locale } from "@/i18n/config";
import { IntlProvider } from "@/i18n/intl-provider";
import "./globals.css";

export async function generateMetadata(): Promise<Metadata> {
  // The tab title and the description a browser surfaces are user-visible copy,
  // so they come out of the catalogue like everything else.
  const t = await getTranslations("meta");
  return {
    title: t("title"),
    description: t("description"),
  };
}

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Read the per-request nonce injected by middleware. Next.js App Router
  // propagates this nonce to its own inline RSC streaming scripts when it
  // detects a nonce-bearing Content-Security-Policy header on the response.
  const nonce = (await headers()).get("x-nonce") ?? undefined;

  // Resolved by src/i18n/request.ts: sp_locale cookie, then Accept-Language,
  // then Russian.
  const locale = (await getLocale()) as Locale;
  const messages = await getMessages();

  return (
    <html lang={htmlLang(locale)}>
      <body>
        <IntlProvider
          locale={locale}
          messages={messages as Record<string, unknown>}
          timeZone={process.env.SP_CONSOLE_TIMEZONE ?? "Asia/Tashkent"}
        >
          <Providers nonce={nonce}>{children}</Providers>
        </IntlProvider>
      </body>
    </html>
  );
}
