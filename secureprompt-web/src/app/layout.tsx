import type { Metadata } from "next";
import type { ReactNode } from "react";
import { headers } from "next/headers";
import { Providers } from "@/components/providers";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecurePrompt",
  description: "LLM security gateway — governance dashboard",
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Read the per-request nonce injected by middleware. Next.js App Router
  // propagates this nonce to its own inline RSC streaming scripts when it
  // detects a nonce-bearing Content-Security-Policy header on the response.
  const nonce = (await headers()).get("x-nonce") ?? undefined;

  return (
    <html lang="en">
      <body>
        <Providers nonce={nonce}>{children}</Providers>
      </body>
    </html>
  );
}
