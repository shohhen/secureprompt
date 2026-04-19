import { test, expect } from "@playwright/test";

/**
 * VALIDATION 5-02-02 — unauthenticated dashboard access redirects to /login
 * with callbackUrl preserved. No backend required (pure src/proxy.ts gate).
 */
test.use({ storageState: { cookies: [], origins: [] } });

test("unauthenticated GET / redirects to /login?callbackUrl=%2F", async ({ page }) => {
  const response = await page.goto("/", { waitUntil: "domcontentloaded" });
  expect(response, "navigation response present").not.toBeNull();
  expect(new URL(page.url()).pathname).toBe("/login");
  expect(new URL(page.url()).searchParams.get("callbackUrl")).toBe("/");
});

test("unauthenticated GET /usage redirects preserving callbackUrl", async ({ page }) => {
  await page.goto("/usage?from=2026-01-01", { waitUntil: "domcontentloaded" });
  const url = new URL(page.url());
  expect(url.pathname).toBe("/login");
  expect(url.searchParams.get("callbackUrl")).toBe("/usage?from=2026-01-01");
});
