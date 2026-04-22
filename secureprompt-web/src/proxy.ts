/**
 * Next.js 16 proxy — auth guard + security headers (merged from middleware.ts).
 *
 * Next.js 16 only allows one file: src/proxy.ts.  This replaces both the
 * old middleware.ts (CSP / security headers) and the initial auth-only proxy.
 *
 * Behaviour per request:
 *   1. Unauthenticated → /login with callbackUrl preserved.
 *   2. Authenticated on /login → redirect to callbackUrl or "/".
 *   3. All responses get nonce-based CSP + X-Frame-Options + Referrer-Policy
 *      + X-Content-Type-Options headers.
 */
import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { buildCsp } from "@/lib/csp";

export default auth((req) => {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const csp = buildCsp(nonce);

  const { nextUrl } = req;
  const isLogin = nextUrl.pathname === "/login";

  let response: Response;

  if (!req.auth && !isLogin) {
    const url = new URL("/login", nextUrl);
    url.searchParams.set("callbackUrl", nextUrl.pathname + nextUrl.search);
    response = NextResponse.redirect(url);
  } else if (req.auth && isLogin) {
    const cb = nextUrl.searchParams.get("callbackUrl") ?? "/";
    response = NextResponse.redirect(new URL(cb, nextUrl));
  } else {
    const requestHeaders = new Headers(req.headers);
    requestHeaders.set("x-nonce", nonce);
    response = NextResponse.next({ request: { headers: requestHeaders } });
  }

  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set("X-Content-Type-Options", "nosniff");

  return response;
});

export const config = {
  // Exclude: API routes, Next internals, favicon, fonts (air-gap static).
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|fonts/).*)"],
};
