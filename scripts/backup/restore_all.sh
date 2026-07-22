#!/usr/bin/env sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=/dev/null
. "$DIR/lib_common.sh"

SRC=${1:?usage: restore_all.sh BACKUP_SUBDIR}
[ -d "$SRC" ] || { echo "restore_all: no such dir $SRC" >&2; exit 1; }
log "restore_all: <- $SRC"
sh "$DIR/restore_postgres.sh"  "$SRC"
sh "$DIR/restore_clickhouse.sh" "$SRC"
sh "$DIR/restore_qdrant.sh"    "$SRC"
log "restore_all: complete"
