#!/usr/bin/env sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=/dev/null
. "$DIR/lib_common.sh"; . "$DIR/lib_crypto.sh"
umask 077

OUTDIR=${1:?usage: backup_clickhouse.sh OUTDIR}
: "${CLICKHOUSE_HOST:=clickhouse}"; : "${CLICKHOUSE_PORT:=9000}"
: "${CLICKHOUSE_DB:=secureprompt}"; : "${CLICKHOUSE_USER:=default}"
: "${CLICKHOUSE_PASSWORD:=}"; : "${CH_BACKUP_MOUNT:=/var/lib/clickhouse/backups}"
_name="ch-$(sp_timestamp).zip"
trap 'rm -f "$CH_BACKUP_MOUNT/$_name"' EXIT   # never leave a plaintext CH backup on the shared mount

# clickhouse-client talks to the server; the server writes the .zip onto its
# 'backups' disk (a container-local volume). We then read it back over the
# client's filesystem mount (the backup image shares that volume) and seal it.
_ch() { clickhouse-client --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" \
        --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" "$@"; }

log "clickhouse: BACKUP DATABASE $CLICKHOUSE_DB -> Disk(backups,$_name)"
_ch --query "BACKUP DATABASE \`$CLICKHOUSE_DB\` TO Disk('backups', '$_name')"

sp_seal "$CH_BACKUP_MOUNT/$_name" "$OUTDIR/clickhouse.zip.enc"
printf '%s' "$_name" > "$OUTDIR/clickhouse.name"   # remember the disk-relative name
rm -f "$CH_BACKUP_MOUNT/$_name"
log "clickhouse: sealed $(wc -c < "$OUTDIR/clickhouse.zip.enc") bytes"
