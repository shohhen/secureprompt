# Backup runner: client tools for all three stores + openssl/xxd + the scripts.
#
# Base: debian:bookworm-slim (glibc), NOT alpine. Two reasons:
#  - ClickHouse only ships a glibc client binary (no official musl/alpine
#    build); `apk add clickhouse` is not a thing on alpine's repos.
#  - Debian bookworm's own `postgresql-client` apt package is pinned to v15,
#    which mismatches the v16 Postgres server used in docker-compose.yml.
# So both client binaries are copied in from their own upstream images
# instead of installed from bookworm's package repo, which keeps versions
# aligned with the stores they actually talk to.
FROM postgres:16-bookworm AS pg-client
FROM clickhouse/clickhouse-server:24.8 AS ch-client

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      openssl \
      xxd \
      libpq5 \
    && rm -rf /var/lib/apt/lists/*

# pg_dump / pg_restore, v16 (matches the postgres:16-alpine server in
# docker-compose.yml). libpq.so.5, which they link against, comes from the
# libpq5 apt package installed above.
COPY --from=pg-client /usr/lib/postgresql/16/bin/pg_dump /usr/lib/postgresql/16/bin/pg_restore /usr/bin/

# ClickHouse ships one multi-call binary that dispatches on argv[0]; the
# official image already exposes it under every subcommand name via symlinks
# (clickhouse-client, clickhouse-local, ...). We only need the client, so
# copy the real binary once and create the one symlink our scripts invoke.
COPY --from=ch-client /usr/bin/clickhouse /usr/bin/clickhouse
RUN ln -s /usr/bin/clickhouse /usr/bin/clickhouse-client

WORKDIR /opt/backup
COPY *.sh ./
RUN chmod +x ./*.sh

ENV BACKUP_DIR=/backups
ENTRYPOINT ["sh", "backup_all.sh"]
