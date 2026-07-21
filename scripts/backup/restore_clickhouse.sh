#!/usr/bin/env sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=/dev/null
. "$DIR/lib_common.sh"; . "$DIR/lib_crypto.sh"
umask 077

OUTDIR=${1:?usage: restore_clickhouse.sh OUTDIR}
: "${CLICKHOUSE_HOST:=clickhouse}"; : "${CLICKHOUSE_PORT:=9000}"
: "${CLICKHOUSE_DB:=secureprompt}"; : "${CLICKHOUSE_USER:=default}"
: "${CLICKHOUSE_PASSWORD:=}"; : "${CH_BACKUP_MOUNT:=/var/lib/clickhouse/backups}"
_name=$(cat "$OUTDIR/clickhouse.name")
trap 'rm -f "$CH_BACKUP_MOUNT/$_name"' EXIT   # never leave a decrypted CH backup on the shared mount

_ch() { clickhouse-client --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" \
        --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" "$@"; }

log "clickhouse: verify+decrypt -> Disk(backups,$_name)"
sp_open "$OUTDIR/clickhouse.zip.enc" "$CH_BACKUP_MOUNT/$_name"   # aborts on bad MAC
# sp_open (umask 077) writes the decrypted artifact as this container's user
# (root, uid 0) mode 0600. The clickhouse-server process itself runs as a
# non-root uid (101, "clickhouse" -- confirmed against the official 24.8
# image) inside its own container, so it cannot open a root-owned 0600 file:
# `RESTORE DATABASE ... FROM Disk('backups', ...)` fails with CANNOT_OPEN_FILE
# / errno 13 Permission denied. Root bypasses permission checks when reading,
# which is why the symmetric backup-side read (CH-owned file, read by this
# root container) never hits this. Widen to world-readable so the server can
# open it; this directory is the internal `clickhouse_backups` Docker volume,
# mounted only by the clickhouse and backup services (not host-exposed), and
# the file is immediately removed after RESTORE (or by the EXIT trap).
chmod 644 "$CH_BACKUP_MOUNT/$_name"
log "clickhouse: DROP + RESTORE DATABASE $CLICKHOUSE_DB"
_ch --query "DROP DATABASE IF EXISTS \`$CLICKHOUSE_DB\`" >/dev/null
_ch --query "RESTORE DATABASE \`$CLICKHOUSE_DB\` FROM Disk('backups', '$_name')" >/dev/null
rm -f "$CH_BACKUP_MOUNT/$_name"
log "clickhouse: restore complete"
