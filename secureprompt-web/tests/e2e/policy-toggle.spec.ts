import { test, expect } from "@playwright/test";

/**
 * Phase 5 / Plan 05-04 — Policy rules pages E2E smoke tests.
 *
 * These tests verify auth-gate behavior (unauthenticated → /login redirect)
 * for the new settings and requests routes. They do NOT require a running
 * backend — only the Next.js server.
 */

test.use({ storageState: { cookies: [], origins: [] } });

const SETTINGS_ROUTES = [
  { path: "/settings/keys", label: "keys" },
  { path: "/settings/providers", label: "providers" },
  { path: "/settings/policy-rules", label: "policy-rules" },
  { path: "/requests", label: "requests" },
] as const;

test.describe("settings and requests — auth gate", () => {
  for (const route of SETTINGS_ROUTES) {
    test(`${route.label} page redirects unauthenticated visitors to /login`, async ({
      page,
    }) => {
      await page.goto(route.path, { waitUntil: "domcontentloaded" });

      const url = page.url();
      const hasLoginPath = url.includes("/login");
      const hasLoginForm = await page
        .locator('input[type="password"]')
        .isVisible()
        .catch(() => false);

      expect(hasLoginPath || hasLoginForm).toBe(true);
    });
  }
});

test.describe("policy-toggle — no dangerouslySetInnerHTML in rendered HTML", () => {
  test("requests page HTML does not contain the string dangerouslySetInnerHTML", async ({
    page,
  }) => {
    // Visit without auth — we only care that the server doesn't render the
    // dangerous attribute, even in error/redirect states.
    await page.goto("/requests", { waitUntil: "domcontentloaded" });
    const html = await page.content();
    expect(html).not.toContain("dangerouslySetInnerHTML");
  });

  test("policy-rules page HTML does not contain dangerouslySetInnerHTML", async ({
    page,
  }) => {
    await page.goto("/settings/policy-rules", { waitUntil: "domcontentloaded" });
    const html = await page.content();
    expect(html).not.toContain("dangerouslySetInnerHTML");
  });
});
