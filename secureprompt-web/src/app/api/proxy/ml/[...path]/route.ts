import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";

// Forward dashboard ML calls (e.g. /api/proxy/ml/v1/rag-check) to the ML
// sidecar inside the compose network. Browsers can't reach
// `http://secureprompt-ml:8080` directly, so the dashboard goes through
// this same-origin proxy. Authenticated sessions only.
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
]);

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

  const search = req.nextUrl.search ?? "";
  const target = `${ML_BASE}/${pathParts.join("/")}${search}`;
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
