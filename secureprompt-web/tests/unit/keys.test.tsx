/**
 * Phase 5 / Plan 05-04 — API Keys unit tests.
 *
 * Tests CreateKeyDialog and DataTable rendering with mocked hooks.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// ── CreateKeyDialog smoke ─────────────────────────────────────────────────────

// Mock use-keys before importing the component
vi.mock("@/lib/hooks/use-keys", () => ({
  useKeys: vi.fn(() => ({ data: [], isLoading: false })),
  useCreateKey: vi.fn(() => ({
    mutateAsync: vi.fn(),
    isPending: false,
  })),
  useRevokeKey: vi.fn(() => ({
    mutate: vi.fn(),
    isPending: false,
  })),
}));

// sonner mock
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { CreateKeyDialog } from "@/app/(dashboard)/settings/keys/create-key-dialog";

describe("CreateKeyDialog", () => {
  it("renders the trigger button", () => {
    render(<CreateKeyDialog />);
    expect(screen.getByRole("button", { name: /create key/i })).toBeInTheDocument();
  });

  it("opens dialog on button click", () => {
    render(<CreateKeyDialog />);
    fireEvent.click(screen.getByRole("button", { name: /create key/i }));
    expect(screen.getByText(/create api key/i)).toBeInTheDocument();
  });

  it("shows name input in the dialog", () => {
    render(<CreateKeyDialog />);
    fireEvent.click(screen.getByRole("button", { name: /create key/i }));
    expect(screen.getByLabelText(/key name/i)).toBeInTheDocument();
  });
});

// ── KeyResponse type contract ─────────────────────────────────────────────────

describe("KeyResponse type contracts", () => {
  /**
   * The plaintext key is returned exactly once, by `POST /v1/keys`. The list
   * endpoint must never carry it.
   *
   * WS6-4 rewrote this test. It used to slice `use-keys.ts` between
   * `indexOf("export interface KeyResponse")` and
   * `indexOf("export interface CreateKeyResponse")` — and once those
   * interfaces became aliases onto the codegen, BOTH `indexOf` calls returned
   * -1, so `expect(block).not.toContain("api_key")` was asserting that the
   * empty string does not contain "api_key". It would have passed forever,
   * including on a `KeyResponse` that did leak the key. Only its sibling
   * assertion failing gave the change away.
   *
   * It now reads the OpenAPI document the types are generated FROM, which is
   * the same document the gateway serves and the same one
   * `openapi_router_contract.rs` checks against the router — so this asserts
   * the published contract rather than the punctuation of one TypeScript file.
   */
  const spec = JSON.parse(
    readFileSync(
      resolve(process.cwd(), "../secureprompt-schemas/openapi/v1/openapi.json"),
      "utf-8",
    ),
  ) as {
    components: {
      schemas: Record<string, { properties?: Record<string, unknown> }>;
    };
  };

  function props(schema: string): string[] {
    const s = spec.components.schemas[schema];
    // Premise: an absent or empty schema would make every assertion below
    // vacuous — exactly the failure mode this rewrite exists to fix.
    expect(s, `${schema} is missing from openapi.json`).toBeTruthy();
    const keys = Object.keys(s.properties ?? {});
    expect(keys.length, `${schema} declares no properties`).toBeGreaterThan(2);
    return keys;
  }

  it("KeyResponse does not include api_key (prefix only)", () => {
    expect(props("KeyResponse")).not.toContain("api_key");
    expect(props("KeyResponse")).toContain("prefix");
  });

  it("CreateKeyResponse is the only one that carries the plaintext", () => {
    // The positive control for the assertion above: if `api_key` were absent
    // everywhere, "KeyResponse does not include api_key" would be satisfied by
    // a document that describes no plaintext key at all.
    expect(props("CreateKeyResponse")).toContain("api_key");
  });
});

// ── DataTable smoke ───────────────────────────────────────────────────────────

import { DataTable } from "@/components/data-table/data-table";
import type { ColumnDef } from "@tanstack/react-table";

interface Row {
  name: string;
  value: number;
}

const cols: ColumnDef<Row>[] = [
  { accessorKey: "name", header: "Name" },
  { accessorKey: "value", header: "Value" },
];

describe("DataTable", () => {
  it("renders empty state message", () => {
    render(
      <DataTable
        columns={cols}
        data={[]}
        emptyMessage="Nothing here."
      />,
    );
    expect(screen.getByText("Nothing here.")).toBeInTheDocument();
  });

  it("renders loading state", () => {
    render(
      <DataTable columns={cols} data={[]} isLoading />,
    );
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  it("renders row data", () => {
    render(
      <DataTable
        columns={cols}
        data={[{ name: "Alice", value: 42 }]}
      />,
    );
    expect(screen.getByText("Alice")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("renders column headers", () => {
    render(<DataTable columns={cols} data={[]} />);
    expect(screen.getByText("Name")).toBeInTheDocument();
    expect(screen.getByText("Value")).toBeInTheDocument();
  });
});
