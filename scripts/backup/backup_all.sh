#!/usr/bin/env sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=/dev/null
. "$DIR/lib_common.sh"

_sub=$(sp_backup_subdir)
log "backup_all: -> $_sub"
sh "$DIR/backup_postgres.sh"  "$_sub"
sh "$DIR/backup_clickhouse.sh" "$_sub"
sh "$DIR/backup_qdrant.sh"    "$_sub"
_artifacts=$(ls -1 "$_sub")
{
  echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "artifacts:"
  printf '%s\n' "$_artifacts"
} > "$_sub/MANIFEST"
log "backup_all: complete; pruning retention (keep $RETENTION_DAILY)"
prune_retention
printf '%s\n' "$_sub"
