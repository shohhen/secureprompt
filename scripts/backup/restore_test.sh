#!/usr/bin/env sh
# End-to-end backup/restore proof across all three stores. Run from repo root
# with the compose stack UP. Seeds a sentinel into each store, backs up, wipes
# the sentinel, restores, and asserts the sentinel returns. Exits non-zero on
# any mismatch. Intended to be captured into the KPI evidence doc.
set -eu
export BACKUP_DIR="./backups"
SENT="sentinel-$(date -u +%s)"
KEY="$SENT-key"          # one key for the whole run, passed into the containers
DC="docker compose"

echo "== seed sentinels ($SENT) =="
$DC exec -T postgres psql -U secureprompt -d secureprompt -c \
  "CREATE TABLE IF NOT EXISTS backup_sentinel(v text); INSERT INTO backup_sentinel VALUES ('$SENT');"
$DC exec -T clickhouse clickhouse-client --query \
  "CREATE TABLE IF NOT EXISTS secureprompt.backup_sentinel(v String) ENGINE=MergeTree ORDER BY v"
$DC exec -T clickhouse clickhouse-client --query \
  "INSERT INTO secureprompt.backup_sentinel VALUES ('$SENT')"
# Qdrant: ensure a collection + a sentinel point.
curl -fsS -X PUT "http://localhost:6333/collections/policy_rag" \
  -H 'Content-Type: application/json' \
  -d '{"vectors":{"size":4,"distance":"Cosine"}}' >/dev/null 2>&1 || true
curl -fsS -X PUT "http://localhost:6333/collections/policy_rag/points" \
  -H 'Content-Type: application/json' \
  -d "{\"points\":[{\"id\":424242,\"vector\":[0.1,0.2,0.3,0.4],\"payload\":{\"sentinel\":\"$SENT\"}}]}" >/dev/null

echo "== backup (via the backup profile container) =="
$DC --profile backup run --rm \
  -e SECUREPROMPT_BACKUP_KEY="$KEY" backup > /tmp/backup_out.txt
SUB=$(grep -Eo '/backups/[0-9]{8}-[0-9]{6}' /tmp/backup_out.txt | tail -1)
echo "backup subdir: $SUB"

echo "== destroy sentinels =="
$DC exec -T postgres psql -U secureprompt -d secureprompt -c "DROP TABLE backup_sentinel;"
$DC exec -T clickhouse clickhouse-client --query "DROP TABLE secureprompt.backup_sentinel"
curl -fsS -X POST "http://localhost:6333/collections/policy_rag/points/delete" \
  -H 'Content-Type: application/json' -d '{"points":[424242]}' >/dev/null

echo "== restore =="
$DC --profile backup run --rm \
  -e SECUREPROMPT_BACKUP_KEY="$KEY" --entrypoint sh backup \
  restore_all.sh "$SUB"

echo "== verify =="
PG=$($DC exec -T postgres psql -U secureprompt -d secureprompt -tAc \
  "SELECT v FROM backup_sentinel" | tr -d '[:space:]')
CH=$($DC exec -T clickhouse clickhouse-client --query \
  "SELECT v FROM secureprompt.backup_sentinel" | tr -d '[:space:]')
QD=$(curl -fsS "http://localhost:6333/collections/policy_rag/points/424242" \
  | sed -n 's/.*"sentinel":"\([^"]*\)".*/\1/p')

fail=0
[ "$PG" = "$SENT" ] || { echo "FAIL postgres: got '$PG'"; fail=1; }
[ "$CH" = "$SENT" ] || { echo "FAIL clickhouse: got '$CH'"; fail=1; }
[ "$QD" = "$SENT" ] || { echo "FAIL qdrant: got '$QD'"; fail=1; }
[ "$fail" = 0 ] && echo "RESTORE TEST PASSED: all three stores returned $SENT" || echo "RESTORE TEST FAILED"
exit "$fail"
