/**
 * Settings → License unit tests.
 *
 * Pattern: vitest + @testing-library/react + happy-dom (matches keys.test.tsx,
 * policy-rules.test.tsx). No component-test harness exists in the repo — tests
 * mock hooks and sonner, then render the client component directly.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, fireEvent, waitFor } from "@testing-library/react";
import { renderWithIntl as render } from "../utils/intl";

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock("next-auth/react", () => ({
  useSession: vi.fn(() => ({
    data: { role: "admin" },
    status: "authenticated",
  })),
}));

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const mockMutateAsync = vi.fn();
const mockMutate = vi.fn();

vi.mock("@/lib/hooks/use-license", () => ({
  useLicense: vi.fn(() => ({
    data: {
      customer_name: "Acme Corp",
      lic_id: "lic_abc123",
      expires_at: "2027-01-01T00:00:00Z",
      features: ["pii_redaction", "audit_log"],
      status: "Valid",
      source: "db",
    },
    isLoading: false,
  })),
  useActivateLicense: vi.fn(() => ({
    mutateAsync: mockMutateAsync,
    isPending: false,
  })),
  useRemoveLicense: vi.fn(() => ({
    mutate: mockMutate,
    isPending: false,
  })),
}));

import { LicenseClient } from "@/app/(dashboard)/settings/license/license-client";
import * as sonner from "sonner";

// ── Status card renders ───────────────────────────────────────────────────────

describe("LicenseClient — status card", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows customer name from the license status", () => {
    render(<LicenseClient />);
    expect(screen.getByText("Acme Corp")).toBeInTheDocument();
  });

  it("shows Valid status badge", () => {
    render(<LicenseClient />);
    expect(screen.getByText("Valid")).toBeInTheDocument();
  });

  it("shows license features as badges", () => {
    render(<LicenseClient />);
    expect(screen.getByText("pii_redaction")).toBeInTheDocument();
    expect(screen.getByText("audit_log")).toBeInTheDocument();
  });

  it("shows expiry date", () => {
    render(<LicenseClient />);
    // The date is formatted by toLocaleDateString — just check the year appears
    expect(screen.getByText(/2027/)).toBeInTheDocument();
  });
});

// ── Activate flow ─────────────────────────────────────────────────────────────

describe("LicenseClient — activate", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockMutateAsync.mockResolvedValue({
      customer_name: "Acme Corp",
      lic_id: "lic_abc123",
      expires_at: "2027-01-01T00:00:00Z",
      features: ["pii_redaction"],
      status: "Valid",
      source: "db",
    });
  });

  it("renders the Activate button and textarea", () => {
    render(<LicenseClient />);
    expect(screen.getByRole("button", { name: /activate/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/activate a new license token/i)).toBeInTheDocument();
  });

  it("calls PUT /v1/license with the token on Activate", async () => {
    render(<LicenseClient />);
    const textarea = screen.getByLabelText(/activate a new license token/i);
    fireEvent.change(textarea, { target: { value: "my-compact-token" } });
    fireEvent.click(screen.getByRole("button", { name: /activate/i }));

    await waitFor(() => {
      expect(mockMutateAsync).toHaveBeenCalledWith({ token: "my-compact-token" });
    });
  });

  it("shows success toast after successful activation", async () => {
    render(<LicenseClient />);
    const textarea = screen.getByLabelText(/activate a new license token/i);
    fireEvent.change(textarea, { target: { value: "my-compact-token" } });
    fireEvent.click(screen.getByRole("button", { name: /activate/i }));

    await waitFor(() => {
      expect(sonner.toast.success).toHaveBeenCalledWith("License activated.");
    });
  });

  it("shows inline error on 400 invalid signature", async () => {
    const { ApiError } = await import("@/lib/api-fetch");
    mockMutateAsync.mockRejectedValueOnce(
      new ApiError("invalid license signature", { status: 400, code: "invalid_signature" }),
    );

    render(<LicenseClient />);
    const textarea = screen.getByLabelText(/activate a new license token/i);
    fireEvent.change(textarea, { target: { value: "bad-token" } });
    fireEvent.click(screen.getByRole("button", { name: /activate/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/invalid license signature/i);
    });
  });
});

// ── Remove flow ───────────────────────────────────────────────────────────────

describe("LicenseClient — remove", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // confirm() is called before remove — stub it to return true
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  it("shows Remove license button when source is db", () => {
    render(<LicenseClient />);
    expect(screen.getByRole("button", { name: /remove license/i })).toBeInTheDocument();
  });

  it("calls DELETE /v1/license on Remove confirm", () => {
    render(<LicenseClient />);
    fireEvent.click(screen.getByRole("button", { name: /remove license/i }));
    expect(mockMutate).toHaveBeenCalled();
  });
});

// ── Source audit ──────────────────────────────────────────────────────────────

import { readFileSync } from "fs";
import { resolve } from "path";

describe("License source audit", () => {
  const files = [
    "src/app/(dashboard)/settings/license/license-client.tsx",
    "src/app/(dashboard)/settings/license/page.tsx",
    "src/lib/hooks/use-license.ts",
  ];

  for (const file of files) {
    it(`${file} must not use dangerouslySetInnerHTML`, () => {
      const src = readFileSync(resolve(process.cwd(), file), "utf-8");
      expect(src).not.toContain("dangerouslySetInnerHTML");
    });
  }

  it("layout.tsx must include a License nav entry", () => {
    const src = readFileSync(
      resolve(process.cwd(), "src/app/(dashboard)/settings/layout.tsx"),
      "utf-8",
    );
    expect(src).toContain("/settings/license");
    // WS6-3 moved the tab label into the catalogue, so the layout carries the
    // key and settingsNav carries the words. Both halves are asserted.
    expect(src).toContain('key: "license"');
    const nav = JSON.parse(
      readFileSync(resolve(process.cwd(), "src/i18n/messages/en.json"), "utf-8"),
    ) as { settingsNav: Record<string, string> };
    expect(nav.settingsNav.license).toBe("License");
  });
});
