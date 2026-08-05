/**
 * Phase 5 / Plan 05-05 — Budget unit tests.
 *
 * Tests BudgetMeter rendering and BudgetForm behavior with mocked hooks.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithIntl as render } from "../utils/intl";

// ── BudgetMeter ───────────────────────────────────────────────────────────────

import { BudgetMeter } from "@/components/budget/budget-meter";

describe("BudgetMeter", () => {
  it("renders label", () => {
    render(<BudgetMeter label="Daily" used={500} limit={1000} />);
    expect(screen.getByText("Daily")).toBeInTheDocument();
  });

  it("shows used / limit when limit is set", () => {
    render(<BudgetMeter label="Monthly" used={200_000} limit={3_000_000} />);
    // formatTokens: 200k / 3M
    expect(screen.getByText(/200k/)).toBeInTheDocument();
    expect(screen.getByText(/3\.0M/)).toBeInTheDocument();
  });

  it("shows 'unlimited' text when limit is null", () => {
    render(<BudgetMeter label="Daily" used={100} limit={null} />);
    expect(screen.getByText(/unlimited/i)).toBeInTheDocument();
  });

  it("renders a progressbar role", () => {
    render(<BudgetMeter label="Daily" used={50} limit={100} />);
    expect(screen.getByRole("progressbar")).toBeInTheDocument();
  });

  it("progressbar aria-valuenow equals used", () => {
    render(<BudgetMeter label="Daily" used={42} limit={200} />);
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "42");
  });
});

// ── use-budget hook type contract ─────────────────────────────────────────────

describe("use-budget type contracts", () => {
  it("exports useBudget and useUpdateBudget", async () => {
    const mod = await import("@/lib/hooks/use-budget");
    expect(typeof mod.useBudget).toBe("function");
    expect(typeof mod.useUpdateBudget).toBe("function");
  });
});

// ── BudgetForm smoke ──────────────────────────────────────────────────────────

vi.mock("@/lib/hooks/use-budget", () => ({
  useBudget: vi.fn(() => ({
    data: {
      daily_token_limit: 100_000,
      monthly_token_limit: 3_000_000,
      behavior: "warn",
      daily_used: 12_000,
      monthly_used: 200_000,
    },
    isLoading: false,
  })),
  useUpdateBudget: vi.fn(() => ({
    mutateAsync: vi.fn(),
    isPending: false,
  })),
}));

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { BudgetForm } from "@/app/(dashboard)/settings/workspace/budget-form";
import * as useBudgetMod from "@/lib/hooks/use-budget";

describe("BudgetForm", () => {
  it("renders daily and monthly labels", () => {
    render(<BudgetForm workspaceId="00000000-0000-0000-0000-000000000001" />);
    expect(screen.getByText("Daily")).toBeInTheDocument();
    expect(screen.getByText("Monthly")).toBeInTheDocument();
  });

  it("renders the save button", () => {
    render(<BudgetForm workspaceId="00000000-0000-0000-0000-000000000001" />);
    expect(
      screen.getByRole("button", { name: /save budget settings/i }),
    ).toBeInTheDocument();
  });

  it("renders three behavior radio options", () => {
    render(<BudgetForm workspaceId="00000000-0000-0000-0000-000000000001" />);
    expect(screen.getByRole("radio", { name: /block/i })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /warn/i })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /flag/i })).toBeInTheDocument();
  });

  it("shows loading state when isLoading is true", () => {
    vi.mocked(useBudgetMod.useBudget).mockReturnValueOnce({
      data: undefined,
      isLoading: true,
    } as ReturnType<typeof useBudgetMod.useBudget>);
    render(<BudgetForm workspaceId="00000000-0000-0000-0000-000000000001" />);
    expect(screen.getByText(/loading budget/i)).toBeInTheDocument();
  });
});
