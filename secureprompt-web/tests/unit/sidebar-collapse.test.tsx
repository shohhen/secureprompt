import { render, screen, fireEvent } from "@testing-library/react";
import { describe, test, expect, vi } from "vitest";
import { Sidebar } from "@/components/layout/sidebar";

// usePathname is used inside Sidebar
vi.mock("next/navigation", () => ({ usePathname: () => "/usage", useRouter: () => ({ prefetch: vi.fn() }) }));

describe("Sidebar collapse behavior", () => {
  test("renders nav item labels when not collapsed", () => {
    render(<Sidebar collapsed={false} />);
    expect(screen.getByText("Usage")).toBeVisible();
  });

  test("hides nav item labels when collapsed", () => {
    render(<Sidebar collapsed={true} />);
    // Labels should be present in DOM but visually hidden (max-w-0 opacity-0)
    const label = screen.getByText("Usage");
    expect(label).toHaveClass("opacity-0");
  });

  test("shows logo text when not collapsed", () => {
    render(<Sidebar collapsed={false} />);
    expect(screen.getByText("SecurePrompt")).toBeVisible();
  });

  test("hides logo text when collapsed", () => {
    render(<Sidebar collapsed={true} />);
    // opacity-0 is on the wrapper span, not the text node itself
    const logoText = screen.getByText("SecurePrompt");
    expect(logoText.parentElement).toHaveClass("opacity-0");
  });

  test("shows runtime status card when not collapsed", () => {
    render(<Sidebar collapsed={false} />);
    expect(screen.getByText("Runtime Status")).toBeInTheDocument();
  });

  test("shows only status dot when collapsed", () => {
    render(<Sidebar collapsed={true} />);
    expect(screen.queryByText("Runtime Status")).not.toBeInTheDocument();
  });
});
