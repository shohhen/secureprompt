/**
 * TDD — error handling: 404 not-found page.
 *
 * Next.js uses src/app/not-found.tsx as the 404 handler. It must:
 *   1. Show a 404 / "not found" heading.
 *   2. Provide a link back to the root "/" so users can recover.
 */

import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";

// Mock next/link — renders as a plain <a> in tests.
vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

// Component under test — doesn't exist yet; tests will fail until we create it.
import NotFound from "@/app/not-found";

describe("NotFound page", () => {
  it("renders a heading that mentions 404 or 'not found'", () => {
    render(<NotFound />);
    const heading = screen.getByRole("heading");
    expect(heading).toBeInTheDocument();
    expect(heading.textContent).toMatch(/404|not found/i);
  });

  it("has a link to the root dashboard path '/'", () => {
    render(<NotFound />);
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("href", "/");
  });

  it("link text is human-readable (not blank)", () => {
    render(<NotFound />);
    const link = screen.getByRole("link");
    expect(link.textContent?.trim().length).toBeGreaterThan(0);
  });
});
