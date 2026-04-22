"use client";

import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api-fetch";

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  const description =
    error instanceof ApiError
      ? error.message
      : "An unexpected error occurred. Try again or contact support.";

  return (
    <div className="flex flex-col items-center justify-center gap-4 p-8 text-center">
      <h2 className="text-xl font-semibold">Something went wrong</h2>
      <p className="text-muted-foreground text-sm max-w-sm">{description}</p>
      <Button onClick={reset}>Try again</Button>
    </div>
  );
}
