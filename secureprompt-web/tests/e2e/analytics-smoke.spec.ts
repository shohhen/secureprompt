import { test, expect } from "@playwright/test";

/**
 * Phase 5 / Plan 05-03 — Analytics pages smoke test (end-to-end).
 *
 * Verifies that the four analytics routes exist and redirect unauthenticated
 * visitors to /login (auth gate).
 *
 * These tests intentionally do NOT require a running backend — they only
 * check that the Next.js middleware/RSC auth gate redirects properly.
 */

test.use({ storageState: { cookies: [], origins: [] } });

const ANALYTICS_ROUTES = [
  { path: "/usage", label: "usage" },
  { path: "/cost", label: "cost" },
  { path: "/policy", label: "policy" },
  { path: "/latency", label: "latency" },
] as const;

test.describe("analytics-smoke — auth gate", () => {
  for (const route of ANALYTICS_ROUTES) {
    test(`${route.label} page redirects unauthenticated visitors to /login`, async ({
      page,
    }) => {
      await page.goto(route.path, { waitUntil: "domcontentloaded" });

      // Either the URL is /login or the page contains a login form.
      const url = page.url();
      const onLogin = url.includes("/login");
      const hasLoginForm = await page
        .getByRole("button", { name: /sign in/i })
        .isVisible()
        .catch(() => false);

      expect(
        onLogin || hasLoginForm,
        `${route.label} page should redirect to login, got ${url}`,
      ).toBe(true);
    });
  }
});
