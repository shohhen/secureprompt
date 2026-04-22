/**
 * TDD — merged proxy retains CSP security-header behaviour.
 *
 * Next.js 16 forbids having both src/middleware.ts and src/proxy.ts.
 * middleware.ts's CSP logic was merged into proxy.ts, and middleware.ts
 * was deleted.  This test guards the pure CSP function that the proxy
 * calls per-request so the behaviour is not silently dropped.
 */

import { describe, it, expect } from "vitest";
import { buildCsp } from "@/lib/csp";

const SECURITY_HEADERS = [
  "X-Frame-Options",
  "Referrer-Policy",
  "X-Content-Type-Options",
] as const;

describe("proxy security headers (merged from middleware.ts)", () => {
  it("buildCsp includes nonce in script-src — same function proxy uses", () => {
    const nonce = Buffer.from("test-uuid").toString("base64");
    const csp = buildCsp(nonce);
    const scriptSrc = csp.match(/script-src([^;]*)/)?.[1] ?? "";
    expect(scriptSrc).toContain(`'nonce-${nonce}'`);
  });

  it("SECURITY_HEADERS constant lists the three headers proxy must set", () => {
    expect(SECURITY_HEADERS).toContain("X-Frame-Options");
    expect(SECURITY_HEADERS).toContain("Referrer-Policy");
    expect(SECURITY_HEADERS).toContain("X-Content-Type-Options");
  });

  it("middleware.ts is absent — only proxy.ts should exist", async () => {
    // Vite resolves dynamic imports statically, so check the filesystem directly.
    const { existsSync } = await import("node:fs");
    const { resolve } = await import("node:path");
    const middlewarePath = resolve(__dirname, "../../src/middleware.ts");
    expect(existsSync(middlewarePath)).toBe(false);
  });
});
