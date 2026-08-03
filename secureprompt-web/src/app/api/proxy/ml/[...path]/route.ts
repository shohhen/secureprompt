import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import type { AppRole } from "@/types/next-auth";

// Forward dashboard ML calls (e.g. /api/proxy/ml/v1/rag-check) to the ML
// sidecar inside the compose network. Browsers can't reach
// `http://secureprompt-ml:8080` directly, so the dashboard goes through
// this same-origin proxy. Authenticated sessions only, and only for the
// three path prefixes the dashboard actually calls — see ALLOWED_ML_PATH.
const ML_BASE =
  process.env.ML_SIDECAR_URL?.replace(/\/+$/, "") ?? "http://secureprompt-ml:8080";

// WS1-5 fix-round: the ML sidecar authenticates every route it serves
// (except /health, /ready, /metrics) via Authorization: Bearer
// <ML_SIDECAR_INTERNAL_TOKEN>. This proxy is the ONLY thing standing
// between the browser and the sidecar (browsers can't reach the
// compose-network hostname directly), so it must attach that shared
// secret on every forwarded request. Same env var the sidecar itself
// reads, surfaced on the gateway via LicenseConfig::internal_token.
const ML_INTERNAL_TOKEN = process.env.ML_SIDECAR_INTERNAL_TOKEN ?? "";

// Stripped before forwarding. `cookie` is NOT a hop-by-hop header in the
// RFC sense — it is here because the NextAuth session JWE lives in it and
// that cookie is where the long-lived refresh token actually resides. The
// sidecar has no use for it and forwarding it would put dashboard session
// material inside the ML process's request logs. (MR1 review M11: the
// comment below used to claim this already held; `cookie` was absent from
// the set, so it did not.)
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "cookie",
]);

// The ONLY sidecar paths the dashboard has a caller for:
//   v1/rag-check                      semantic-search/search-form.tsx
//   v1/scan-file{,/async,/tasks/…}    file-scan/file-scan-api.ts
//   v1/secure-file{,/async,/tasks/…}  file-scan/file-scan-api.ts
//
// MR1 review C5: this proxy attaches ML_SIDECAR_INTERNAL_TOKEN, which is
// the SAME shared secret `/internal/model-key` authenticates with
// (`hmac.compare_digest` in secureprompt-ml/app/main.py). Without an
// allowlist, `if (!session)` was the entire authorization model and any
// dashboard session could drive the model-IP boundary, plus /detect/ner,
// /detect/injection and /embed — detection capacity that is unmetered,
// unaudited, un-rate-limited and completely bypasses the Rust gateway.
//
// Matched against the JOINED path so a prefix collision (`v1/rag-checkX`)
// cannot slip through, and anchored with `(/|$)` rather than `startsWith`.
const ALLOWED_ML_PATH = /^v1\/(rag-check|scan-file|secure-file)(\/|$)/;

// Subset of the above that mutates/consumes real work on the sidecar
// (uploads a document, runs a full NER pass, produces a redacted file).
// `viewer` is the dashboard's read-only role, so it gets search but not
// this. Mirrors the "viewer sees, does not do" line the rest of the
// dashboard draws via `canWrite`/`canReadAllAudit` in `src/lib/roles.ts`.
const SCAN_ML_PATH = /^v1\/(scan-file|secure-file)(\/|$)/;

// An ALLOW list, not a deny list, so a session carrying an unrecognised or
// absent `role` is refused rather than waved through.
const SCAN_ROLES: readonly AppRole[] = ["owner", "admin", "developer", "employee"];

/** Reject traversal and empty segments before any pattern is applied. */
function pathIsWellFormed(pathParts: string[]): boolean {
  return (
    pathParts.length > 0 &&
    pathParts.every((part) => part.length > 0 && part !== "." && part !== "..")
  );
}

function filterHeaders(src: Headers): Headers {
  const out = new Headers();
  src.forEach((value, key) => {
    if (!HOP_BY_HOP.has(key.toLowerCase())) out.set(key, value);
  });
  return out;
}

async function forward(
  req: NextRequest,
  pathParts: string[],
): Promise<NextResponse> {
  const session = await auth();
  if (!session) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const joined = pathParts.join("/");
  if (!pathIsWellFormed(pathParts) || !ALLOWED_ML_PATH.test(joined)) {
    return NextResponse.json(
      { error: "forbidden", detail: "path is not proxied to the ML sidecar" },
      { status: 403 },
    );
  }
  if (SCAN_ML_PATH.test(joined) && !SCAN_ROLES.includes(session.role)) {
    return NextResponse.json(
      { error: "forbidden", detail: "role may not run file scans" },
      { status: 403 },
    );
  }

  const search = req.nextUrl.search ?? "";
  const target = `${ML_BASE}/${joined}${search}`;
  const headers = filterHeaders(req.headers);
  // Overwrite (never forward) whatever Authorization the browser session
  // sent — the sidecar only accepts its own shared secret, and passing the
  // dashboard session's header through would either be ignored or, worse,
  // leak session material to the sidecar.
  headers.set("authorization", `Bearer ${ML_INTERNAL_TOKEN}`);
  const init: RequestInit = {
    method: req.method,
    headers,
    redirect: "manual",
  };
  if (req.method !== "GET" && req.method !== "HEAD") {
    init.body = await req.arrayBuffer();
  }

  const upstream = await fetch(target, init);
  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: filterHeaders(upstream.headers),
  });
}

interface Ctx {
  params: Promise<{ path: string[] }>;
}

export async function GET(req: NextRequest, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function POST(req: NextRequest, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function PUT(req: NextRequest, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function PATCH(req: NextRequest, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function DELETE(req: NextRequest, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
