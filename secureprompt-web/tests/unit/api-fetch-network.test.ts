/**
 * TDD — error handling: NetworkError wrapping in apiFetch.
 *
 * Currently apiFetch lets TypeError / AbortError bubble through as-is.
 * These tests drive the addition of NetworkError so callers can distinguish
 * "the server said something wrong" (ApiError) from
 * "we never reached the server" (NetworkError).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Stub next-auth so module resolution doesn't explode in the test env.
vi.mock("next-auth/react", () => ({
  getSession: vi.fn().mockResolvedValue(null),
  signOut: vi.fn(),
}));
vi.mock("@/lib/auth", () => ({
  auth: vi.fn().mockResolvedValue(null),
}));

import { apiFetch, ApiError, NetworkError } from "@/lib/api-fetch";

describe("apiFetch — NetworkError wrapping", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("throws NetworkError when fetch rejects with TypeError", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new TypeError("Failed to fetch"));

    await expect(apiFetch("/v1/test")).rejects.toBeInstanceOf(NetworkError);
  });

  it("NetworkError has isNetworkError=true", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new TypeError("Network error"));

    const err = await apiFetch("/v1/test").catch((e) => e);
    expect((err as NetworkError).isNetworkError).toBe(true);
  });

  it("NetworkError message is human-readable", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new TypeError("Failed to fetch"));

    const err: unknown = await apiFetch("/v1/test").catch((e: unknown) => e);
    expect((err as NetworkError).message).toMatch(/network|connection|failed to fetch/i);
  });

  it("throws NetworkError when fetch rejects with AbortError (timeout)", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(
      new DOMException("The user aborted a request.", "AbortError"),
    );

    await expect(apiFetch("/v1/test")).rejects.toBeInstanceOf(NetworkError);
  });

  it("AbortError NetworkError message mentions timeout or abort", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(
      new DOMException("Aborted", "AbortError"),
    );

    const err: unknown = await apiFetch("/v1/test").catch((e: unknown) => e);
    expect((err as NetworkError).message).toMatch(/timeout|aborted|abort/i);
  });

  it("still throws ApiError for a 500 HTTP response (regression)", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: { message: "Internal server error", type: "secureprompt_error" },
        }),
        { status: 500, headers: { "content-type": "application/json" } },
      ),
    );

    const err: unknown = await apiFetch("/v1/test").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(500);
  });

  it("parses nested error envelope { error: { code, message } } correctly", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: {
            message: "Not found",
            type: "secureprompt_error",
            code: "not_found",
          },
        }),
        { status: 404, headers: { "content-type": "application/json" } },
      ),
    );

    const err: unknown = await apiFetch("/v1/test").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("not_found");
    expect((err as ApiError).message).toBe("Not found");
  });

  it("parses budget_exceeded code from nested envelope", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: {
            message: "Budget exceeded",
            type: "secureprompt_error",
            code: "budget_exceeded",
          },
        }),
        { status: 402, headers: { "content-type": "application/json" } },
      ),
    );

    const err: unknown = await apiFetch("/v1/test", { signOutOn401: false }).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("budget_exceeded");
  });
});
