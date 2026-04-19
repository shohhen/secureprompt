import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// VALIDATION 5-02-03: shadcn primitives smoke — each renders independently
// with the expected semantic role and a concrete attribute we can assert.

describe("shadcn primitives smoke", () => {
  it("Button renders as <button> with label text", () => {
    render(<Button>Sign in</Button>);
    const btn = screen.getByRole("button", { name: /sign in/i });
    expect(btn).toBeInTheDocument();
    expect(btn.tagName).toBe("BUTTON");
  });

  it("Input renders with the given type attribute", () => {
    render(<Input type="email" placeholder="you@company.com" />);
    const input = screen.getByPlaceholderText("you@company.com");
    expect(input).toBeInTheDocument();
    expect(input).toHaveAttribute("type", "email");
  });

  it("Label renders as a <label> element with for binding", () => {
    render(
      <>
        <Label htmlFor="email">Email</Label>
        <Input id="email" type="email" />
      </>,
    );
    const label = screen.getByText("Email");
    expect(label.tagName).toBe("LABEL");
    expect(label).toHaveAttribute("for", "email");
  });

  it("Card composes header/title/content with semantic structure", () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Usage</CardTitle>
        </CardHeader>
        <CardContent>
          <p>Content</p>
        </CardContent>
      </Card>,
    );
    expect(screen.getByText("Usage")).toBeInTheDocument();
    expect(screen.getByText("Content")).toBeInTheDocument();
  });
});
