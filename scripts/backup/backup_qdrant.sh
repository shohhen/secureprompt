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
    # Create a snapshot; response .result.name is the snapshot filename.
    _name=$(curl -fsS -X POST "$QDRANT_URL/collections/$_c/snapshots" \
        | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
    [ -n "$_name" ] || { log "qdrant: no snapshot name for $_c (collection missing?)"; continue; }
    _snap="$OUTDIR/qdrant-$_c.snapshot"
    curl -fsS "$QDRANT_URL/collections/$_c/snapshots/$_name" -o "$_snap"
    sp_seal "$_snap" "$OUTDIR/qdrant-$_c.snapshot.enc"
    rm -f "$_snap"
    _snap=""
    # Clean up the server-side snapshot so they don't accumulate.
    curl -fsS -X DELETE "$QDRANT_URL/collections/$_c/snapshots/$_name" >/dev/null || true
    log "qdrant: sealed $_c"
done
