"use client";

/**
 * WS6-3 — locale switcher.
 *
 * Writes the `sp_locale` cookie through a Server Action and lets the router
 * re-render; because the locale lives in a cookie rather than the URL, the
 * operator stays on exactly the page they were reading.
 */
import { useTransition } from "react";
import { useLocale, useTranslations } from "next-intl";
import { Languages, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { LOCALES, LOCALE_LABELS, type Locale } from "@/i18n/config";
import { setLocale } from "@/i18n/set-locale";

export function LocaleSwitcher() {
  const active = useLocale() as Locale;
  const t = useTranslations("header");
  const [pending, startTransition] = useTransition();

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="icon"
          aria-label={t("changeLanguage")}
          disabled={pending}
        >
          <Languages className="size-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-48">
        <DropdownMenuLabel>{t("language")}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {LOCALES.map((locale) => (
          <DropdownMenuItem
            key={locale}
            className="cursor-pointer gap-2"
            onClick={() => {
              if (locale === active) return;
              startTransition(async () => {
                await setLocale(locale);
              });
            }}
          >
            <Check
              className={locale === active ? "size-4 opacity-100" : "size-4 opacity-0"}
            />
            {/* i18n-exempt: endonyms — each locale names itself in its own script */}
            {LOCALE_LABELS[locale]}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
