"use client";

import { useState } from "react";
import { ContactModal } from "./ContactModal";

export function TalkToUsButton({
  label,
  className,
  variant = "link",
}: {
  label: string;
  className?: string;
  variant?: "link" | "primary";
}) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className={`talk-btn talk-btn-${variant} ${className ?? ""}`}
      >
        {label}
      </button>
      <ContactModal isOpen={open} onClose={() => setOpen(false)} />
    </>
  );
}
