/**
 * CSP header assertions — VALIDATION 5-08-02 / T-05-06
 *
 * Verifies that the Next.js app sets a strict Content-Security-Policy header
 * on key routes (/login and /usage). The CSP must contain:
 *   - default-src 'self'
 *   - script-src 'self'
 *   - connect-src 'self' <API_URL>
 *   - frame-ancestors 'none'
 *
 * These are defined in secureprompt-web/next.config.ts headers() — no
 * runtime server is needed; we parse the next.config.ts directly to assert
 * the header value that will be emitted.
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { pathToFileURL } from "node:url";

// ---------------------------------------------------------------------------
// Load the CSP value from next.config.ts without spinning up a Next server.
// ---------------------------------------------------------------------------

async function loadCspFromConfig(): Promise<string> {
  // next.config.ts exports a NextConfig object. We import it via dynamic
  // import (tsx handles the TypeScript transform in vitest).
  const configPath = path.resolve(
    __dirname,
    "../../next.config.ts",
  );
  // Use dynamic import — vitest with tsx plugin handles .ts files.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mod = (await import(pathToFileURL(configPath).href)) as any;
  const config = mod.default ?? mod;

  if (typeof config.headers !== "function") {
    throw new Error("next.config.ts must export a headers() function");
  }

  const headerGroups: Array<{
    source: string;
    headers: Array<{ key: string; value: string }>;
  }> = await config.headers();

  // Find the wildcard (catch-all) group.
  const catchAll = headerGroups.find((g) => g.source === "/(.*)");
  if (!catchAll) {
    throw new Error(
      "next.config.ts headers() must contain a source: '/(.*)'  catch-all group",
    );
  }

  const cspHeader = catchAll.headers.find(
    (h) => h.key === "Content-Security-Policy",
  );
  if (!cspHeader) {
    throw new Error(
      "No Content-Security-Policy header found in the '/(.*)'  header group",
    );
  }

  return cspHeader.value;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("CSP headers (next.config.ts)", () => {
  it("includes default-src 'self'", async () => {
    const csp = await loadCspFromConfig();
    expect(csp).toContain("default-src 'self'");
  });

  it("includes script-src 'self'", async () => {
    const csp = await loadCspFromConfig();
    expect(csp).toContain("script-src 'self'");
  });

  it("includes connect-src 'self'", async () => {
    const csp = await loadCspFromConfig();
    expect(csp).toContain("connect-src 'self'");
  });

  it("includes frame-ancestors 'none'", async () => {
    const csp = await loadCspFromConfig();
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it("includes base-uri 'self'", async () => {
    const csp = await loadCspFromConfig();
    expect(csp).toContain("base-uri 'self'");
  });

  it("includes form-action 'self'", async () => {
    const csp = await loadCspFromConfig();
    expect(csp).toContain("form-action 'self'");
  });

  it("does not allow unsafe-eval in script-src", async () => {
    const csp = await loadCspFromConfig();
    // Ensure 'unsafe-eval' is absent from script-src directive
    const scriptSrcMatch = csp.match(/script-src([^;]*)/);
    if (scriptSrcMatch) {
      expect(scriptSrcMatch[1]).not.toContain("unsafe-eval");
    }
  });

  it("applies to /login route (catch-all source covers it)", async () => {
    const configPath = path.resolve(__dirname, "../../next.config.ts");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mod = (await import(pathToFileURL(configPath).href)) as any;
    const config = mod.default ?? mod;
    const headerGroups: Array<{ source: string }> =
      await config.headers();
    // /login matches the catch-all /(.*) pattern
    const hasCatchAll = headerGroups.some((g) => g.source === "/(.*)");
    expect(hasCatchAll).toBe(true);
  });
});
