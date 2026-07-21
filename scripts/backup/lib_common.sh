#!/usr/bin/env sh
# Shared config/logging/retention for the backup scripts.

: "${BACKUP_DIR:=/backups}"
: "${RETENTION_DAILY:=7}"
: "${RETENTION_WEEKLY:=4}"

log() { printf '%s [backup] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

# NOTE: date is passed in / stamped by the runner, not generated inside a
# workflow — here it is a real backup runtime, so wall-clock is correct.
sp_timestamp() { date -u +%Y%m%d-%H%M%S; }

sp_backup_subdir() {
    _d="$BACKUP_DIR/$(sp_timestamp)"
    mkdir -p "$_d"
    printf '%s' "$_d"
}

# Keep the RETENTION_DAILY newest top-level dated dirs under BACKUP_DIR;
# delete the rest. (Weekly rollup: dated dirs are retained by count here;
# a weekly tier can be layered later — documented, not silently dropped.
# RETENTION_WEEKLY is accepted/defaulted above for forward compatibility
# but is currently a no-op stub — no weekly-tier logic exists yet.)
prune_retention() {
    [ -d "$BACKUP_DIR" ] || return 0
    # List dated dirs newest-first, skip the first RETENTION_DAILY, remove rest.
    ls -1 "$BACKUP_DIR" 2>/dev/null \
        | grep -E '^[0-9]{8}-[0-9]{6}$' \
        | sort -r \
        | tail -n +"$((RETENTION_DAILY + 1))" \
        | while IFS= read -r _old; do
              log "pruning old backup $_old"
              rm -rf "$BACKUP_DIR/$_old"
          done
}
