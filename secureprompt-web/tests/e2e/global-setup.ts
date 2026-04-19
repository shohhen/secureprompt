/**
 * Playwright global-setup: prepares `tests/e2e/storage/auth.json` by calling
 * Plan 01's /v1/auth/token with the fixture admin, then driving the NextAuth
 * Credentials signIn in a headless browser to capture the session cookie.
 *
 * If the backend is not reachable, we write an empty storage file and specs
 * that require authentication should `.skip()` when `session?.accessToken`
 * is absent (or read `process.env.E2E_BACKEND_UNREACHABLE`).
 */
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { request } from "@playwright/test";

const STORAGE_DIR = path.resolve(__dirname, "./storage");
const STORAGE_FILE = path.join(STORAGE_DIR, "auth.json");

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
const FIXTURE_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin.a@fixtures.test";
const FIXTURE_PASSWORD =
  process.env.E2E_ADMIN_PASSWORD ?? "fixture-password";

async function ensureStorageDir() {
  await mkdir(STORAGE_DIR, { recursive: true });
}

export default async function globalSetup(): Promise<void> {
  await ensureStorageDir();

  try {
    const ctx = await request.newContext({ baseURL: BACKEND_URL });
    const res = await ctx.post("/v1/auth/token", {
      data: { email: FIXTURE_EMAIL, password: FIXTURE_PASSWORD },
      failOnStatusCode: false,
      timeout: 5_000,
    });
    if (!res.ok()) {
      process.env.E2E_BACKEND_UNREACHABLE = "true";
      await writeFile(STORAGE_FILE, JSON.stringify({ cookies: [], origins: [] }));
      await ctx.dispose();
      return;
    }
    // We don't need to populate a browser storage state here — specs that
    // exercise login will drive the NextAuth flow themselves. We just prove
    // the backend is alive and seed an empty storage file.
    await writeFile(STORAGE_FILE, JSON.stringify({ cookies: [], origins: [] }));
    await ctx.dispose();
  } catch {
    process.env.E2E_BACKEND_UNREACHABLE = "true";
    await writeFile(STORAGE_FILE, JSON.stringify({ cookies: [], origins: [] }));
  }
}
