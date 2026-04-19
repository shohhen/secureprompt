import type { NextConfig } from "next";
import path from "node:path";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

const csp = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self' data:",
  "img-src 'self' data: blob:",
  `connect-src 'self' ${API_URL}`,
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");

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
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "X-Content-Type-Options", value: "nosniff" },
        ],
      },
    ];
  },
};

export default nextConfig;
