#!/usr/bin/env sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=/dev/null
. "$DIR/lib_common.sh"; . "$DIR/lib_crypto.sh"
umask 077

OUTDIR=${1:?usage: restore_qdrant.sh OUTDIR}
: "${QDRANT_URL:=http://qdrant:6333}"
: "${QDRANT_COLLECTIONS:=policy_rag prompt_similarity}"

# _snap holds the path of the (at most one) decrypted plaintext snapshot
# currently on disk for the collection being processed. The trap fires on
# any exit (success, error, or set -e abort mid-loop -- e.g. a bad MAC in
# sp_open or a failed curl upload) and removes it. On the happy path each
# iteration also removes it explicitly and resets _snap to "" -- so at most
# one plaintext snapshot ever exists at a time, and a mid-loop failure still
# leaves nothing decrypted behind.
_snap=""
trap 'rm -f "$_snap"' EXIT   # never leave a decrypted plaintext qdrant snapshot, even on failure

for _c in $QDRANT_COLLECTIONS; do
    _enc="$OUTDIR/qdrant-$_c.snapshot.enc"
    [ -f "$_enc" ] || { log "qdrant: no artifact for $_c, skipping"; continue; }
    log "qdrant: verify+decrypt $_c"
    _snap="$OUTDIR/qdrant-$_c.snapshot.restore"
    sp_open "$_enc" "$_snap"   # aborts on bad MAC, does not write $_snap
    log "qdrant: upload+recover $_c (priority=snapshot)"
    curl -fsS -X POST \
        "$QDRANT_URL/collections/$_c/snapshots/upload?priority=snapshot" \
        -F "snapshot=@$_snap" >/dev/null
    rm -f "$_snap"
    _snap=""
    log "qdrant: restored $_c"
done
