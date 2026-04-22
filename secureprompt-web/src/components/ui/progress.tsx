import * as React from "react";
import { cn } from "@/lib/utils";

function Progress({
  className,
  value = 0,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { value?: number }) {
  const normalized = Math.max(0, Math.min(100, value));
  return (
    <div className={cn("relative h-1.5 w-full overflow-hidden rounded-full bg-secondary", className)} {...props}>
      <div className="h-full bg-primary transition-all duration-300" style={{ width: `${normalized}%` }} />
    </div>
  );
}

export { Progress };
