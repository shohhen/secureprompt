"use client";

import { Toaster as Sonner, type ToasterProps } from "sonner";

const Toaster = ({ ...props }: ToasterProps) => {
  return (
    <Sonner
      className="toaster group"
      toastOptions={{
        classNames: {
          toast:
            "group toast group-[.toaster]:bg-[var(--color-surface-raised)] group-[.toaster]:text-[var(--color-foreground)] group-[.toaster]:border-[var(--color-border)] group-[.toaster]:shadow-lg",
          description: "group-[.toast]:text-[var(--color-muted-foreground)]",
          actionButton:
            "group-[.toast]:bg-[var(--color-primary)] group-[.toast]:text-[var(--color-primary-foreground)]",
          cancelButton:
            "group-[.toast]:bg-[var(--color-muted)] group-[.toast]:text-[var(--color-muted-foreground)]",
        },
      }}
      {...props}
    />
  );
};

export { Toaster };
