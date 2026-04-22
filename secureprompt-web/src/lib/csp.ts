const DEFAULT_API_URL = "http://localhost:8080";

/**
 * Builds a Content-Security-Policy string for a single request.
 * Must be called per-request (in middleware) so the nonce is unique each time.
 *
 * 'strict-dynamic' allows Next.js to load dynamically-split chunks from a
 * nonced parent script. 'self' is kept as a fallback for older browsers that
 * don't understand 'strict-dynamic'.
 */
export function buildCsp(nonce: string): string {
  const apiUrl = (process.env.NEXT_PUBLIC_API_URL ?? DEFAULT_API_URL).replace(
    /\/+$/,
    "",
  );

  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src 'self' 'unsafe-inline'",
    "font-src 'self' data:",
    "img-src 'self' data: blob:",
    `connect-src 'self' ${apiUrl}`,
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");
}
