#!/usr/bin/env sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=/dev/null
. "$DIR/lib_common.sh"; . "$DIR/lib_crypto.sh"

OUTDIR=${1:?usage: backup_postgres.sh OUTDIR}
: "${PGHOST:=postgres}"; : "${PGPORT:=5432}"; : "${PGUSER:=secureprompt}"
: "${PGPASSWORD:=secureprompt}"; : "${PGDATABASE:=secureprompt}"
export PGPASSWORD

log "postgres: pg_dump $PGDATABASE@$PGHOST"
_plain="$OUTDIR/postgres.dump"
pg_dump -Fc -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -f "$_plain"
sp_seal "$_plain" "$OUTDIR/postgres.dump.enc"
rm -f "$_plain"   # never leave plaintext in the backup dir
log "postgres: sealed $(wc -c < "$OUTDIR/postgres.dump.enc") bytes"
