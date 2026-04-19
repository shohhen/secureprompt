/**
 * Next.js 16 proxy (renamed from middleware.ts — 05-PATTERNS Pitfall #6).
 *
 * Gates dashboard routes: any unauthenticated request to a non-/login path
 * is redirected to /login with the original path preserved as callbackUrl.
 * Authenticated users visiting /login are redirected to callbackUrl or "/".
 *
 * IMPORTANT: file path MUST be `src/proxy.ts`, NOT `src/middleware.ts`.
 * Next.js 16 emits a deprecation warning for the legacy name.
 */
import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";

export default auth((req) => {
  const { nextUrl } = req;
  const isLogin = nextUrl.pathname === "/login";

  if (!req.auth && !isLogin) {
    const url = new URL("/login", nextUrl);
    url.searchParams.set("callbackUrl", nextUrl.pathname + nextUrl.search);
    return NextResponse.redirect(url);
  }

  if (req.auth && isLogin) {
    const cb = nextUrl.searchParams.get("callbackUrl") ?? "/";
    return NextResponse.redirect(new URL(cb, nextUrl));
  }

  return NextResponse.next();
});

export const config = {
  // Exclude: API routes, Next internals, favicon, fonts (air-gap static).
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|fonts/).*)"],
};
