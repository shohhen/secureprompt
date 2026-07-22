#!/usr/bin/env sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=/dev/null
. "$DIR/lib_common.sh"; . "$DIR/lib_crypto.sh"
umask 077

OUTDIR=${1:?usage: restore_postgres.sh OUTDIR}
: "${PGHOST:=postgres}"; : "${PGPORT:=5432}"; : "${PGUSER:=secureprompt}"
: "${PGPASSWORD:=secureprompt}"; : "${PGDATABASE:=secureprompt}"
export PGPASSWORD

_plain="$OUTDIR/postgres.dump.restore"
trap 'rm -f "$_plain"' EXIT   # never leave a decrypted plaintext dump, even on failure
log "postgres: verify+decrypt"
sp_open "$OUTDIR/postgres.dump.enc" "$_plain"   # aborts on bad MAC
log "postgres: pg_restore --clean --if-exists into $PGDATABASE"
pg_restore --clean --if-exists --no-owner --single-transaction \
    -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" "$_plain"
rm -f "$_plain"
log "postgres: restore complete"
