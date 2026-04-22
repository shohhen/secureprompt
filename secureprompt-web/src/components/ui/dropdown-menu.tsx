"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

interface DropdownMenuContextValue {
  open: boolean;
  setOpen: (open: boolean) => void;
}

const DropdownMenuContext = React.createContext<DropdownMenuContextValue>({
  open: false,
  setOpen: () => {},
});

function DropdownMenu({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open]);

  return (
    <DropdownMenuContext.Provider value={{ open, setOpen }}>
      <div ref={ref} className="relative inline-block">
        {children}
      </div>
    </DropdownMenuContext.Provider>
  );
}

function DropdownMenuTrigger({
  asChild,
  children,
  ...props
}: React.HTMLAttributes<HTMLElement> & { asChild?: boolean }) {
  const { open, setOpen } = React.useContext(DropdownMenuContext);
  const child = asChild ? (children as React.ReactElement) : <button {...props}>{children}</button>;
  return React.cloneElement(child as React.ReactElement<React.HTMLAttributes<HTMLElement>>, {
    onClick: (e: React.MouseEvent) => {
      e.stopPropagation();
      setOpen(!open);
      const existing = (child as React.ReactElement<React.HTMLAttributes<HTMLElement>>).props.onClick;
      if (existing) existing(e as React.MouseEvent<HTMLElement>);
    },
    "aria-expanded": open,
  });
}

function DropdownMenuContent({
  className,
  align = "start",
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { align?: "start" | "end" | "center" }) {
  const { open } = React.useContext(DropdownMenuContext);
  if (!open) return null;
  return (
    <div
      className={cn(
        "absolute z-50 mt-1 min-w-[9rem] overflow-hidden rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-xl",
        align === "end" && "right-0",
        align === "center" && "left-1/2 -translate-x-1/2",
        align === "start" && "left-0",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

function DropdownMenuItem({
  className,
  onClick,
  children,
  disabled,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { disabled?: boolean }) {
  const { setOpen } = React.useContext(DropdownMenuContext);
  return (
    <div
      role="menuitem"
      onClick={
        disabled
          ? undefined
          : (e) => {
              onClick?.(e);
              setOpen(false);
            }
      }
      className={cn(
        "relative flex cursor-default select-none items-center rounded-md px-2 py-1.5 text-sm outline-none transition-colors",
        disabled ? "pointer-events-none opacity-50" : "hover:bg-accent hover:text-accent-foreground cursor-pointer",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

function DropdownMenuSeparator({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("-mx-1 my-1 h-px bg-border", className)} {...props} />;
}

function DropdownMenuLabel({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("px-2 py-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground", className)}
      {...props}
    />
  );
}

function DropdownMenuGroup({ children }: { children: React.ReactNode }) {
  return <div role="group">{children}</div>;
}

export {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuLabel,
  DropdownMenuGroup,
};
