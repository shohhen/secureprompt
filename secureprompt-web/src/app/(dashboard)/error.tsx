"use client";

import { useEffect } from "react";
import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api-fetch";

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const t = useTranslations("errors");

  useEffect(() => {
    console.error(error);
  }, [error]);

  // ApiError carries a message produced by the gateway, which is localised
  // server-side; anything else is ours to phrase.
  const description = error instanceof ApiError ? error.message : t("unexpected");

  return (
    <div className="flex flex-col items-center justify-center gap-4 p-8 text-center">
      <h2 className="text-xl font-semibold">{t("title")}</h2>
      <p className="text-muted-foreground text-sm max-w-sm">{description}</p>
      <Button onClick={reset}>{t("retry")}</Button>
    </div>
  );
}
