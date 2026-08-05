"use client";

/**
 * A Client Component on purpose: the 404 page has to render even when the
 * server-side request context is unavailable, and it is a static leaf with no
 * data of its own, so the bundle cost is a link and a heading.
 */
import Link from "next/link";
import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  const t = useTranslations("notFound");
  return (
    <div className="flex flex-col items-center justify-center gap-4 p-8 text-center">
      <h1 className="text-2xl font-bold">{t("title")}</h1>
      <p className="text-muted-foreground text-sm">
        {t("description")}
      </p>
      <Button asChild>
        <Link href="/">{t("cta")}</Link>
      </Button>
    </div>
  );
}
