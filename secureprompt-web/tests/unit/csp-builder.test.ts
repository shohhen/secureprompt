/**
 * TDD — CSP nonce support: buildCsp() pure function.
 *
 * The static next.config.ts CSP blocks Next.js App Router's inline RSC
 * streaming scripts (self.__next_f.push). Fix: move CSP to middleware where
 * a per-request nonce can be injected. buildCsp(nonce) is the pure function
 * that middleware calls.
 */

import { describe, it, expect } from "vitest";

// Module under test — doesn't exist yet; all tests fail until we create it.
import { buildCsp } from "@/lib/csp";

const TEST_NONCE = "abc123testNonce==";

describe("buildCsp", () => {
  it("includes the provided nonce in script-src", () => {
    const csp = buildCsp(TEST_NONCE);
    expect(csp).toContain(`'nonce-${TEST_NONCE}'`);
    // Verify nonce is scoped to script-src, not another directive
    const scriptSrc = csp.match(/script-src([^;]*)/)?.[1] ?? "";
    expect(scriptSrc).toContain(`'nonce-${TEST_NONCE}'`);
  });

  it("includes 'strict-dynamic' in script-src so dynamically loaded chunks work", () => {
    const csp = buildCsp(TEST_NONCE);
    const scriptSrc = csp.match(/script-src([^;]*)/)?.[1] ?? "";
    expect(scriptSrc).toContain("'strict-dynamic'");
  });

  it("includes 'self' in script-src as fallback for older browsers", () => {
    const csp = buildCsp(TEST_NONCE);
    const scriptSrc = csp.match(/script-src([^;]*)/)?.[1] ?? "";
    expect(scriptSrc).toContain("'self'");
  });

  it("does not allow unsafe-inline in script-src", () => {
    const csp = buildCsp(TEST_NONCE);
    const scriptSrc = csp.match(/script-src([^;]*)/)?.[1] ?? "";
    expect(scriptSrc).not.toContain("'unsafe-inline'");
  });

  it("includes default-src 'self'", () => {
    const csp = buildCsp(TEST_NONCE);
    expect(csp).toContain("default-src 'self'");
  });

  it("includes frame-ancestors 'none'", () => {
    const csp = buildCsp(TEST_NONCE);
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it("includes base-uri 'self'", () => {
    const csp = buildCsp(TEST_NONCE);
    expect(csp).toContain("base-uri 'self'");
  });

  it("includes form-action 'self'", () => {
    const csp = buildCsp(TEST_NONCE);
    expect(csp).toContain("form-action 'self'");
  });

  it("includes connect-src 'self'", () => {
    const csp = buildCsp(TEST_NONCE);
    expect(csp).toContain("connect-src 'self'");
  });

  it("produces a different nonce value for each call when given a different nonce", () => {
    const csp1 = buildCsp("nonce-one==");
    const csp2 = buildCsp("nonce-two==");
    expect(csp1).not.toBe(csp2);
  });
});
