/**
 * Phase 5 / Plan 05-04 — API Keys unit tests.
 *
 * Tests CreateKeyDialog and DataTable rendering with mocked hooks.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, fireEvent } from "@testing-library/react";
import { renderWithIntl as render } from "../utils/intl";

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
  it("KeyResponse does not include api_key (prefix only)", () => {
    // Type-level check: if api_key existed on KeyResponse, this would fail tsc.
    // Here we verify by inspecting the hook module's exported interface shape
    // by checking the hook file's source for the correct type separation.
    const { readFileSync } = require("fs");
    const { resolve } = require("path");
    const src = readFileSync(
      resolve(process.cwd(), "src/lib/hooks/use-keys.ts"),
      "utf-8",
    );
    // KeyResponse (the GET list type) must NOT have api_key
    // CreateKeyResponse (the POST response type) MUST have api_key
    const keyResponseBlock = src.slice(
      src.indexOf("export interface KeyResponse"),
      src.indexOf("export interface CreateKeyResponse"),
    );
    expect(keyResponseBlock).not.toContain("api_key");
    expect(src).toContain("CreateKeyResponse");
    const createResponseBlock = src.slice(
      src.indexOf("export interface CreateKeyResponse"),
    );
    expect(createResponseBlock).toContain("api_key");
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
