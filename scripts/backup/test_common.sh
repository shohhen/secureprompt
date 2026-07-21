#!/usr/bin/env sh
# Self-test for lib_common.sh. Exits 0 on success, non-zero on failure.
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=/dev/null
. "$DIR/lib_common.sh"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
export BACKUP_DIR="$TMP/backups"; export RETENTION_DAILY=3

# timestamp shape
ts=$(sp_timestamp)
echo "$ts" | grep -Eq '^[0-9]{8}-[0-9]{6}$' || { echo "FAIL: bad timestamp $ts"; exit 1; }

# retention keeps only the newest RETENTION_DAILY dirs
mkdir -p "$BACKUP_DIR"
for d in 20260101-000000 20260102-000000 20260103-000000 20260104-000000 20260105-000000; do
  mkdir -p "$BACKUP_DIR/$d"
done
prune_retention
kept=$(ls -1 "$BACKUP_DIR" | wc -l | tr -d ' ')
[ "$kept" = "3" ] || { echo "FAIL: expected 3 kept, got $kept"; exit 1; }
# the three newest survive
ls "$BACKUP_DIR" | grep -q 20260105-000000 || { echo "FAIL: newest pruned"; exit 1; }
ls "$BACKUP_DIR" | grep -q 20260101-000000 && { echo "FAIL: oldest kept"; exit 1; }

echo "ALL COMMON TESTS PASSED"
