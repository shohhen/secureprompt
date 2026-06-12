# Build stage
FROM node:22-alpine AS builder
WORKDIR /app

# Pin pnpm to a known-good major. `pnpm@latest` introduced
# `ERR_PNPM_IGNORED_BUILDS` as a hard failure when build scripts aren't
# pre-approved in package.json — easy to break the image when the
# upstream tag rolls forward unrelated to anything in this repo.
RUN corepack enable && corepack prepare pnpm@10.18.0 --activate

# Copy lockfile + manifests first for better layer caching
COPY secureprompt-web/package.json secureprompt-web/pnpm-lock.yaml ./

RUN pnpm install --frozen-lockfile

# Copy schemas for codegen, then app source
# Path must match codegen script: ../secureprompt-schemas/... resolves to /secureprompt-schemas from WORKDIR /app
COPY secureprompt-schemas /secureprompt-schemas
COPY secureprompt-web/. ./

# NEXT_PUBLIC_* vars are inlined into the browser bundle at BUILD time, so the
# public API origin must be supplied here (not just at runtime) or the client
# falls back to http://localhost:8080 and every browser API call fails.
ARG NEXT_PUBLIC_API_URL=http://localhost:8080
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}

# Run codegen (openapi-typescript) + build (produces .next/standalone)
RUN pnpm codegen && pnpm build

# Runtime stage — node:22-alpine per CONTEXT D-26 (NOT distroless)
FROM node:22-alpine AS runner
WORKDIR /app

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Explicit COPY of public/ + .next/static/ + .next/standalone/ is REQUIRED.
# Next.js standalone output does NOT auto-copy these (Pitfall #6 in 05-RESEARCH.md).
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
ENV PORT=3000 \
    HOSTNAME="0.0.0.0" \
    NODE_ENV=production

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget --spider -q http://localhost:3000/api/health || exit 1

CMD ["node", "server.js"]
