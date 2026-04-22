import Link from "next/link";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 p-8 text-center">
      <h1 className="text-2xl font-bold">404 — Page not found</h1>
      <p className="text-muted-foreground text-sm">
        The page you're looking for doesn't exist.
      </p>
      <Button asChild>
        <Link href="/">Go to Dashboard</Link>
      </Button>
    </div>
  );
}
