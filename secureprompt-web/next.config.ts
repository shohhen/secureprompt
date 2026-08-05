import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";
import path from "node:path";

const nextConfig: NextConfig = {
  output: "standalone",
  reactStrictMode: true,
  typedRoutes: true,
  // Pin the workspace root so Turbopack does not pick up an unrelated
  // lockfile from a parent directory (causes deep nesting in the standalone
  // bundle output). See https://nextjs.org/docs/app/api-reference/config/next-config-js/turbopack#root-directory.
  turbopack: {
    root: path.resolve(__dirname),
  },
  // Security headers are set per-request by src/middleware.ts (nonce-based CSP).
  // Only _next/static and _next/image assets bypass middleware; those routes
  // are cache-controlled by Next.js itself and carry no sensitive data.
};

// WS6-3 — points next-intl at the per-request locale/message resolver.
// No i18n routing is configured: the locale comes from the `sp_locale` cookie,
// so no URL in the console gains a locale prefix.
const withNextIntl = createNextIntlPlugin("./src/i18n/request.ts");

export default withNextIntl(nextConfig);
