import type { Metadata, Viewport } from "next";
import {
  Inter,
  JetBrains_Mono,
  Instrument_Serif,
  VT323,
  Silkscreen,
} from "next/font/google";
import "./globals.css";
import "./scenes.css";

const inter = Inter({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700", "800"],
  variable: "--font-inter",
  display: "swap",
});
const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-jetbrains",
  display: "swap",
});
const instrumentSerif = Instrument_Serif({
  subsets: ["latin"],
  weight: ["400"],
  style: ["normal", "italic"],
  variable: "--font-serif",
  display: "swap",
});
const vt323 = VT323({
  subsets: ["latin"],
  weight: ["400"],
  variable: "--font-pixel",
  display: "swap",
});
const silkscreen = Silkscreen({
  subsets: ["latin"],
  weight: ["400", "700"],
  variable: "--font-pixel-sm",
  display: "swap",
});

export const metadata: Metadata = {
  title: "SecurePrompt — The security gateway for the AI-native enterprise",
  description:
    "On-premises AI security gateway. Redacts PII and secrets, enforces policy, audits every request — without sending your data to a third-party SaaS.",
  metadataBase: new URL("https://secureprompt.io"),
  openGraph: {
    title: "SecurePrompt — AI security gateway, on-prem first",
    description:
      "Sits between every application, agent, browser, or copilot in your organization and the LLM providers they call.",
    type: "website",
  },
};

export const viewport: Viewport = {
  themeColor: "#F8F8FF",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} ${instrumentSerif.variable} ${vt323.variable} ${silkscreen.variable}`}
    >
      <body>{children}</body>
    </html>
  );
}
