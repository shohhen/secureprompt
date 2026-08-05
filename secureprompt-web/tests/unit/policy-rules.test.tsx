/**
 * Phase 5 / Plan 05-04 — Policy Rules unit tests.
 *
 * Tests priority conflict toast message, toggle rendering, and
 * source-level absence of dangerouslySetInnerHTML.
 */

import { describe, it, expect, vi, type MockInstance } from "vitest";
import { screen, fireEvent, waitFor } from "@testing-library/react";
import { renderWithIntl as render } from "../utils/intl";
import { readFileSync } from "fs";
import { resolve } from "path";
import * as sonner from "sonner";

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock("@/lib/hooks/use-policy-rules", () => ({
  usePolicyRules: vi.fn(() => ({ data: [], isLoading: false })),
  useCreatePolicyRule: vi.fn(() => ({
    mutateAsync: vi.fn().mockRejectedValue(
      Object.assign(new Error("Priority conflict"), { code: "priority_conflict" }),
    ),
    isPending: false,
  })),
  useUpdatePolicyRule: vi.fn(() => ({
    mutateAsync: vi.fn(),
    isPending: false,
  })),
  useDeletePolicyRule: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
  useTogglePolicyRuleEnabled: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
  useTogglePolicyRuleDryRun: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

import { RuleForm } from "@/app/(dashboard)/settings/policy-rules/rule-form";

// ── RuleForm renders ──────────────────────────────────────────────────────────

describe("RuleForm", () => {
  it("renders the form fields when open", () => {
    render(<RuleForm open={true} onOpenChange={vi.fn()} />);
    expect(screen.getByLabelText(/name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/priority/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/action/i)).toBeInTheDocument();
  });

  it("shows priority_conflict toast on conflict error", async () => {
    render(<RuleForm open={true} onOpenChange={vi.fn()} />);

    // Fill name so form is valid
    fireEvent.change(screen.getByLabelText(/name/i), {
      target: { value: "Test Rule" },
    });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));

    await waitFor(() => {
      expect(sonner.toast.error).toHaveBeenCalledWith(
        expect.stringMatching(/priority.*in use/i),
      );
    });
  });

  it("has Enabled and Dry Run checkboxes", () => {
    render(<RuleForm open={true} onOpenChange={vi.fn()} />);
    expect(screen.getByLabelText(/enabled/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/dry run/i)).toBeInTheDocument();
  });

  it("defaults Enabled to checked", () => {
    render(<RuleForm open={true} onOpenChange={vi.fn()} />);
    const enabledCheckbox = screen.getByLabelText(/enabled/i) as HTMLInputElement;
    expect(enabledCheckbox.checked).toBe(true);
  });

  it("defaults Dry Run to unchecked", () => {
    render(<RuleForm open={true} onOpenChange={vi.fn()} />);
    const dryRunCheckbox = screen.getByLabelText(/dry run/i) as HTMLInputElement;
    expect(dryRunCheckbox.checked).toBe(false);
  });
});

// ── Valid actions list ─────────────────────────────────────────────────────────

describe("Valid policy actions", () => {
  it("includes all five required actions in the form", () => {
    render(<RuleForm open={true} onOpenChange={vi.fn()} />);
    const select = screen.getByLabelText(/action/i) as HTMLSelectElement;
    const options = Array.from(select.options).map((o) => o.value);
    expect(options).toContain("allow");
    expect(options).toContain("deny");
    expect(options).toContain("redact");
    expect(options).toContain("transform");
    expect(options).toContain("flag");
  });
});

// ── Source audit: no dangerouslySetInnerHTML ───────────────────────────────────

describe("Policy rules source audit", () => {
  const files = [
    "src/app/(dashboard)/settings/policy-rules/rule-form.tsx",
    "src/app/(dashboard)/settings/policy-rules/policy-rules-panel.tsx",
    "src/app/(dashboard)/settings/policy-rules/page.tsx",
  ];

  for (const file of files) {
    it(`${file} must not use dangerouslySetInnerHTML`, () => {
      const src = readFileSync(resolve(process.cwd(), file), "utf-8");
      expect(src).not.toContain("dangerouslySetInnerHTML");
    });
  }
});
