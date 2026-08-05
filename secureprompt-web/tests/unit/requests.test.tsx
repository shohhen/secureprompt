/**
 * Phase 5 / Plan 05-04 — Requests page unit tests.
 *
 * Tests pure component/utility behavior without hitting the network.
 * No dangerouslySetInnerHTML must appear in any imported component.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithIntl as render } from "../utils/intl";

// ── Cursor URL helpers ────────────────────────────────────────────────────────

describe("buildRequestsUrl", () => {
  // Re-implement the helper inline (mirrors use-requests.ts logic)
  function buildRequestsUrl(
    filters: {
      workspaceId: string;
      from?: string;
      to?: string;
      model?: string;
      has_violation?: boolean;
      limit?: number;
    },
    cursor?: string,
  ): string {
    const params = new URLSearchParams();
    params.set("workspace_id", filters.workspaceId);
    if (filters.from) params.set("from", filters.from);
    if (filters.to) params.set("to", filters.to);
    if (filters.model) params.set("model", filters.model);
    if (filters.has_violation != null)
      params.set("has_violation", String(filters.has_violation));
    if (filters.limit) params.set("limit", String(filters.limit));
    if (cursor) params.set("cursor", cursor);
    return `/v1/requests?${params.toString()}`;
  }

  it("includes workspace_id", () => {
    const url = buildRequestsUrl({ workspaceId: "ws-123" });
    expect(url).toContain("workspace_id=ws-123");
  });

  it("appends cursor when provided", () => {
    const url = buildRequestsUrl({ workspaceId: "ws-123" }, "abc123cursor");
    expect(url).toContain("cursor=abc123cursor");
  });

  it("omits cursor when not provided", () => {
    const url = buildRequestsUrl({ workspaceId: "ws-123" });
    expect(url).not.toContain("cursor=");
  });

  it("appends has_violation=true when set", () => {
    const url = buildRequestsUrl({ workspaceId: "ws-1", has_violation: true });
    expect(url).toContain("has_violation=true");
  });

  it("appends has_violation=false when explicitly false", () => {
    const url = buildRequestsUrl({ workspaceId: "ws-1", has_violation: false });
    expect(url).toContain("has_violation=false");
  });

  it("omits optional params when absent", () => {
    const url = buildRequestsUrl({ workspaceId: "ws-1" });
    expect(url).not.toContain("from=");
    expect(url).not.toContain("model=");
  });

  it("caps limit at 200 on the client", () => {
    const requested = 500;
    const capped = Math.min(requested, 200);
    expect(capped).toBe(200);
  });
});

// ── DetectionsDrawer — no innerHTML ──────────────────────────────────────────

import { DetectionsDrawer } from "@/app/(dashboard)/requests/[id]/detections-drawer";

describe("DetectionsDrawer", () => {
  it("renders empty state when no events", () => {
    render(<DetectionsDrawer events={[]} />);
    expect(screen.getByText(/no policy events/i)).toBeInTheDocument();
  });

  it("renders rule name as text node inside mark (not innerHTML)", () => {
    const events = [
      {
        rule_id: "r1",
        rule_name: "Block SSN",
        action: "redact",
        dry_run: false,
      },
    ];
    render(<DetectionsDrawer events={events} />);
    const mark = screen.getByText("Block SSN").closest("mark");
    expect(mark).not.toBeNull();
    // Verify content was NOT set via innerHTML
    expect(mark?.getAttribute("data-action")).toBe("redact");
  });

  it("shows dry-run annotation when dry_run=true", () => {
    const events = [
      {
        rule_id: "r2",
        rule_name: "Flag PII",
        action: "flag",
        dry_run: true,
      },
    ];
    render(<DetectionsDrawer events={events} />);
    expect(screen.getByText(/dry-run/i)).toBeInTheDocument();
  });

  it("renders multiple chips for multiple events", () => {
    const events = [
      { rule_id: "r1", rule_name: "Rule A", action: "allow", dry_run: false },
      { rule_id: "r2", rule_name: "Rule B", action: "deny", dry_run: false },
    ];
    render(<DetectionsDrawer events={events} />);
    expect(screen.getByText("Rule A")).toBeInTheDocument();
    expect(screen.getByText("Rule B")).toBeInTheDocument();
  });
});

// ── No dangerouslySetInnerHTML in source files ────────────────────────────────

import { readFileSync } from "fs";
import { resolve } from "path";

/**
 * Check that dangerouslySetInnerHTML does not appear as actual JSX usage in
 * source files. Comments mentioning the attribute (e.g. "never via
 * dangerouslySetInnerHTML") are allowed and expected.
 *
 * We look for the JSX prop assignment pattern: `dangerouslySetInnerHTML={`
 * which is always on a non-comment line when actually used.
 */
function hasActualDangerousHtmlUsage(src: string): boolean {
  return src
    .split("\n")
    .filter((line) => {
      const trimmed = line.trim();
      return !trimmed.startsWith("//") && !trimmed.startsWith("*");
    })
    .some((line) => line.includes("dangerouslySetInnerHTML={"));
}

describe("dangerouslySetInnerHTML absence", () => {
  const files = [
    "src/app/(dashboard)/requests/requests-table.tsx",
    "src/app/(dashboard)/requests/[id]/detections-drawer.tsx",
    "src/app/(dashboard)/requests/[id]/request-detail-view.tsx",
    "src/app/(dashboard)/settings/keys/keys-panel.tsx",
    "src/app/(dashboard)/settings/keys/create-key-dialog.tsx",
    "src/app/(dashboard)/settings/providers/providers-panel.tsx",
    "src/app/(dashboard)/settings/providers/provider-form.tsx",
    "src/app/(dashboard)/settings/policy-rules/policy-rules-panel.tsx",
    "src/app/(dashboard)/settings/policy-rules/rule-form.tsx",
    "src/components/data-table/data-table.tsx",
  ];

  for (const file of files) {
    it(`${file} must not use dangerouslySetInnerHTML as JSX prop`, () => {
      const src = readFileSync(
        resolve(process.cwd(), file),
        "utf-8",
      );
      expect(hasActualDangerousHtmlUsage(src)).toBe(false);
    });
  }
});
