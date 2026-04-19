import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright config — Chromium only for Phase 5. Plan 06 may extend to
 * additional browsers once the CI matrix is in place.
 *
 * Global setup hits Plan 01's /v1/auth/token to populate storageState for
 * authenticated specs. Specs that test unauthenticated behavior (e.g.
 * proxy-redirect) should override with `use({ storageState: undefined })`.
 */
const BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:3000";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? [["list"], ["github"]] : "list",
  globalSetup: "./tests/e2e/global-setup.ts",
  use: {
    baseURL: BASE_URL,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    // Per-project / per-spec override if storage/auth.json is absent.
    storageState: "./tests/e2e/storage/auth.json",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: process.env.PLAYWRIGHT_SKIP_WEBSERVER
    ? undefined
    : {
        command: "pnpm dev",
        url: BASE_URL,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      },
});
