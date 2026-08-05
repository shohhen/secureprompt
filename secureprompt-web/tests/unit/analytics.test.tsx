/**
 * Phase 5 / Plan 05-03 — Analytics component unit tests.
 *
 * Tests pure client-side utilities and components only — avoids importing
 * RSC page files (which pull in next-auth / server-only and cannot run in
 * vitest's happy-dom environment).
 *
 * MART_EXPOSURES_REGISTRY is tested here; the per-page MART_EXPOSURES
 * constants are verified at build time by check-mart-exposures.mjs.
 */

import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithIntl as render } from "../utils/intl";

// ── MART_EXPOSURES_REGISTRY ───────────────────────────────────────────────────

import { MART_EXPOSURES_REGISTRY } from "../../src/lib/mart-exposures";

describe("MART_EXPOSURES_REGISTRY", () => {
  it("usage page declares mart_usage_daily", () => {
    expect(MART_EXPOSURES_REGISTRY.usage).toContain("mart_usage_daily");
  });

  it("cost page declares mart_cost_by_model", () => {
    expect(MART_EXPOSURES_REGISTRY.cost).toContain("mart_cost_by_model");
  });

  it("policy page declares mart_policy_violations", () => {
    expect(MART_EXPOSURES_REGISTRY.policy).toContain("mart_policy_violations");
  });

  it("latency page declares mart_latency_pctiles", () => {
    expect(MART_EXPOSURES_REGISTRY.latency).toContain("mart_latency_pctiles");
  });

  it("covers all four analytics routes", () => {
    expect(Object.keys(MART_EXPOSURES_REGISTRY)).toHaveLength(4);
  });
});

// ── WorkspaceFilter smoke ────────────────────────────────────────────────────

import { WorkspaceFilter } from "../../src/components/filters/workspace-filter";

describe("WorkspaceFilter", () => {
  it("renders the first 8 chars of the workspace id", () => {
    const ws = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    render(<WorkspaceFilter workspaceId={ws} />);
    expect(screen.getByText(/a1b2c3d4/)).toBeInTheDocument();
  });

  it("renders the Workspace label", () => {
    render(<WorkspaceFilter workspaceId="00000000-0000-0000-0000-000000000000" />);
    expect(screen.getByText(/workspace/i)).toBeInTheDocument();
  });
});
