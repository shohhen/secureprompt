/**
 * Phase 5 / Plan 05-05 — E2E: budget-exceeded banner.
 *
 * Verifies that dispatching the `sp:budget-exceeded` custom event from the
 * browser causes the Topbar to render the budget-exceeded banner and the
 * "Manage budget" link points to /settings/workspace.
 *
 * This test does NOT require a live API server — it exercises the client-side
 * event listener registered in Topbar.tsx by injecting the event directly.
 */

import { test, expect } from "@playwright/test";

test.describe("budget-exceeded banner", () => {
  test("banner appears when sp:budget-exceeded event fires", async ({ page }) => {
    // Navigate to any authenticated page. Use the dashboard root which loads
    // the layout + Topbar. The global setup seeds a session cookie.
    await page.goto("/");

    // Inject the custom event that api-fetch emits on 402.
    await page.evaluate(() => {
      window.dispatchEvent(
        new CustomEvent("sp:budget-exceeded", {
          detail: { code: "budget_exceeded", message: "Daily token limit exceeded" },
        }),
      );
    });

    // Banner text should now be visible.
    await expect(
      page.getByText(/token budget exceeded/i),
    ).toBeVisible({ timeout: 3000 });

    // "Manage budget" link should point to /settings/workspace.
    const link = page.getByRole("link", { name: /manage budget/i });
    await expect(link).toBeVisible();
    await expect(link).toHaveAttribute("href", "/settings/workspace");
  });

  test("banner is not visible on initial load", async ({ page }) => {
    await page.goto("/");
    await expect(
      page.getByText(/token budget exceeded/i),
    ).not.toBeVisible();
  });
});
