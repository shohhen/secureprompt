# Build stage
FROM node:22-alpine AS builder
WORKDIR /app

# Install pnpm directly instead of via corepack — Node 22's bundled
# corepack can fail signature verification when fetching pnpm from npm
# (the npm signing-key roll-over broke older corepack snapshots).
RUN npm install -g pnpm@10.18.0

COPY secureprompt-marketing/package.json secureprompt-marketing/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY secureprompt-marketing/. ./
RUN pnpm build

# Runtime stage
FROM node:22-alpine AS runner
WORKDIR /app

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3001
ENV PORT=3001 \
    HOSTNAME="0.0.0.0" \
    NODE_ENV=production

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget --spider -q http://localhost:3001/ || exit 1

CMD ["node", "server.js"]
