/**
 * reportClientError — best-effort frontend error telemetry.
 *
 * Posts to POST /v1/telemetry/client-error via apiFetch (auth handled
 * automatically). Silently drops on 401 (apiFetch already calls signOut).
 * Rate-limited to max 10 events per 60-second sliding window per browser tab
 * to prevent log/metric flooding from runaway error loops.
 *
 * Do NOT call reportClientError from within apiFetch itself (loop risk).
 */
import { apiFetch } from "./api-fetch";

const WINDOW_MS = 60_000; // 1 minute
const MAX_EVENTS = 10;

/** Timestamps (Date.now()) of recent reportClientError calls in this window. */
let bucket: number[] = [];

export async function reportClientError(
  component: string,
  error: Error | string,
  context?: Record<string, unknown>,
): Promise<void> {
  // Sliding-window rate limit: drop events beyond MAX_EVENTS per WINDOW_MS.
  const now = Date.now();
  bucket = bucket.filter((t) => now - t < WINDOW_MS);
  if (bucket.length >= MAX_EVENTS) {
    return;
  }
  bucket.push(now);

  const message =
    error instanceof Error ? error.message : String(error);

  try {
    await apiFetch("/v1/telemetry/client-error", {
      method: "POST",
      body: {
        component: component.slice(0, 128),
        message: message.slice(0, 1024),
        url:
          typeof window !== "undefined"
            ? window.location.href.slice(0, 512)
            : "",
        user_agent:
          typeof navigator !== "undefined" ? navigator.userAgent : undefined,
        context,
      },
      // Do NOT trigger another signOut cycle on 401 here — apiFetch already
      // handles that, and calling it again from within a telemetry call creates
      // a re-entry risk.
      signOutOn401: false,
    });
  } catch {
    // Best-effort — swallow all errors to prevent telemetry from masking the
    // original error the caller is trying to report.
  }
}

/** Reset the rate-limit bucket. Exposed for testing only. */
export function _resetBucketForTest(): void {
  bucket = [];
}
