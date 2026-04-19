/**
 * Next.js Route Handler — /api/telemetry
 *
 * Thin wrapper that receives window.onerror / window.onunhandledrejection
 * events from the dashboard layout's global error hook and forwards them
 * to the Rust backend's POST /v1/telemetry/client-error endpoint.
 *
 * This proxy exists so:
 *   1. The browser never directly calls the Rust API from a non-CORS context.
 *   2. The session token is available server-side via auth().
 *   3. The body can be validated/capped before forwarding.
 */
import { NextRequest, NextResponse } from "next/server";
import { apiFetch } from "@/lib/api-fetch";

interface GlobalErrorPayload {
  component?: string;
  message?: string;
  url?: string;
  user_agent?: string;
  context?: Record<string, unknown>;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  let payload: GlobalErrorPayload;
  try {
    payload = (await req.json()) as GlobalErrorPayload;
  } catch {
    return NextResponse.json({ error: "invalid JSON" }, { status: 400 });
  }

  const component =
    typeof payload.component === "string" ? payload.component : "unknown";
  const message =
    typeof payload.message === "string" ? payload.message : "unknown error";
  const url =
    typeof payload.url === "string"
      ? payload.url
      : req.headers.get("referer") ?? "";

  try {
    await apiFetch("/v1/telemetry/client-error", {
      method: "POST",
      body: {
        component: component.slice(0, 128),
        message: message.slice(0, 1024),
        url: url.slice(0, 512),
        user_agent: payload.user_agent,
        context: payload.context,
      },
      signOutOn401: false,
    });
    return new NextResponse(null, { status: 204 });
  } catch {
    // Best-effort: never surface telemetry failures to the browser.
    return new NextResponse(null, { status: 204 });
  }
}
