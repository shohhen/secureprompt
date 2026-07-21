#!/usr/bin/env sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=/dev/null
. "$DIR/lib_common.sh"; . "$DIR/lib_crypto.sh"
umask 077

OUTDIR=${1:?usage: backup_qdrant.sh OUTDIR}
: "${QDRANT_URL:=http://qdrant:6333}"
: "${QDRANT_COLLECTIONS:=policy_rag prompt_similarity}"

# _snap holds the path of the (at most one) plaintext snapshot currently on
# disk for the collection being processed. The trap fires on any exit
# (success, error, or set -e abort mid-loop) and removes it. On the happy
# path each iteration also removes it explicitly and resets _snap to "" —
# so at most one plaintext snapshot ever exists at a time, and a curl/sp_seal
# failure mid-loop still leaves nothing decrypted behind.
_snap=""
trap 'rm -f "$_snap"' EXIT   # never leave a plaintext qdrant snapshot, even on failure

for _c in $QDRANT_COLLECTIONS; do
    log "qdrant: snapshot $_c"
    # Capture the response so curl's own exit status is checked. A piped
    # `curl | sed` reports sed's status (POSIX sh has no pipefail), so a real
    # Qdrant outage would look like an empty name = "collection missing" and the
    # whole backup would exit 0 having written nothing (phantom success).
    #
    # NOTE: deliberately NOT using curl -f here. Qdrant returns HTTP 404 (not
    # 200-with-empty-name) for POST .../snapshots against a collection that
    # doesn't exist -- confirmed empirically. -f would make curl itself exit
    # nonzero on that 404, indistinguishable from a real outage, and the whole
    # backup would abort just because one optional collection was never
    # created. So: capture status+body ourselves and branch on the status —
    # 404 is a legitimate "missing collection, skip"; anything else non-2xx,
    # or a curl transport failure (connection refused / timeout / DNS), is
    # still fatal.
    if ! _resp=$(curl -sS -w '\n%{http_code}' -X POST "$QDRANT_URL/collections/$_c/snapshots"); then
        log "qdrant: create-snapshot request FAILED for $_c (connection error)"; exit 1
    fi
    _code=$(printf '%s\n' "$_resp" | tail -n1)
    _body=$(printf '%s\n' "$_resp" | sed '$d')
    case "$_code" in
        200) ;;
        404) log "qdrant: collection $_c missing, skipping"; continue ;;
        *) log "qdrant: create-snapshot request FAILED for $_c (HTTP $_code)"; exit 1 ;;
    esac
    # Compact JSON {"result":{"name":"...","size":...}}. An empty match here
    # (HTTP 200 but no name) legitimately means the collection is absent -> skip.
    _name=$(printf '%s' "$_body" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
    [ -n "$_name" ] || { log "qdrant: no snapshot for $_c (collection missing?), skipping"; continue; }
    _snap="$OUTDIR/qdrant-$_c.snapshot"
    curl -fsS "$QDRANT_URL/collections/$_c/snapshots/$_name" -o "$_snap"
    sp_seal "$_snap" "$OUTDIR/qdrant-$_c.snapshot.enc"
    rm -f "$_snap"
    _snap=""
    # Clean up the server-side snapshot so they don't accumulate.
    curl -fsS -X DELETE "$QDRANT_URL/collections/$_c/snapshots/$_name" >/dev/null || true
    log "qdrant: sealed $_c"
done
