import type { Config } from "tailwindcss";

// Tailwind 4 reads design tokens from the @theme block in src/app/globals.css.
// This config file exists only to satisfy legacy tooling (shadcn CLI / IDE plugins).
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
};

export default config;
