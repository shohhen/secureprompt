// ESLint 9 flat config for Next.js 16 (required — `next lint` is deprecated).
// See https://nextjs.org/docs/app/api-reference/config/eslint
import nextConfig from "eslint-config-next";
import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

const config = [
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "src/types/api.gen.ts",
      "public/**",
      "tests/e2e/**",
    ],
  },
  ...nextConfig,
  ...nextCoreWebVitals,
  ...nextTypescript,
];

export default config;
