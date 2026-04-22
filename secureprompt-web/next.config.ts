import type { NextConfig } from "next";
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

export default nextConfig;
