/**
 * TDD — error handling: Dashboard error boundary component.
 *
 * Next.js error.tsx receives { error, reset } props and must:
 *   1. Show a "Something went wrong" heading.
 *   2. Render a "Try again" button that calls reset().
 *   3. Surface the ApiError.message when the error is an ApiError.
 */

import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ApiError } from "@/lib/api-fetch";

// Component under test — doesn't exist yet; tests will fail until we create it.
import DashboardError from "@/app/(dashboard)/error";

describe("DashboardError boundary", () => {
  it("renders a 'Something went wrong' heading", () => {
    render(<DashboardError error={new Error("boom")} reset={vi.fn()} />);
    expect(screen.getByRole("heading")).toBeInTheDocument();
    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
  });

  it("renders a Try again button", () => {
    render(<DashboardError error={new Error("boom")} reset={vi.fn()} />);
    expect(
      screen.getByRole("button", { name: /try again/i }),
    ).toBeInTheDocument();
  });

  it("calls reset when Try again is clicked", () => {
    const reset = vi.fn();
    render(<DashboardError error={new Error("boom")} reset={reset} />);
    fireEvent.click(screen.getByRole("button", { name: /try again/i }));
    expect(reset).toHaveBeenCalledOnce();
  });

  it("shows ApiError message in the description area", () => {
    const err = new ApiError("Provider credential is invalid", {
      status: 422,
      code: "invalid_credential",
    });
    render(<DashboardError error={err} reset={vi.fn()} />);
    expect(screen.getByText("Provider credential is invalid")).toBeInTheDocument();
  });

  it("shows a generic fallback message for non-ApiError", () => {
    render(
      <DashboardError error={new Error("unexpected crash")} reset={vi.fn()} />,
    );
    // The description <p> should show a safe generic message, not the raw JS error.
    expect(
      screen.getByText(/an unexpected error|contact support/i, { selector: "p" }),
    ).toBeInTheDocument();
  });
});
