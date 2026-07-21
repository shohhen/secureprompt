#!/usr/bin/env sh
# Authenticated encryption for backup artifacts: AES-256-CBC + HMAC-SHA256
# (encrypt-then-MAC). openssl `enc -aes-256-gcm` is deliberately NOT used —
# the enc command drops the GCM tag, giving encryption without integrity.
# The enc key and MAC key are domain-separated derivations of the single
# secret SECUREPROMPT_BACKUP_KEY, so the same bytes never key both.
#
# On-disk format (contract — do not change):
#   sealed     = IV(16 raw bytes) || AES-256-CBC ciphertext
#   sealed.mac = HMAC-SHA256(sealed)   (hex-encoded, one line)

# Derive SP_ENC_KEY and SP_MAC_KEY (64 hex chars each) from the backup key.
sp_derive_keys() {
    if [ -z "${SECUREPROMPT_BACKUP_KEY:-}" ]; then
        echo "sp_crypto: SECUREPROMPT_BACKUP_KEY is unset — refusing to proceed" >&2
        return 1
    fi
    SP_ENC_KEY=$(printf '%s' 'secureprompt-backup-enc-v1' \
        | openssl dgst -sha256 -mac HMAC -macopt "key:$SECUREPROMPT_BACKUP_KEY" -r \
        | cut -d' ' -f1)
    SP_MAC_KEY=$(printf '%s' 'secureprompt-backup-mac-v1' \
        | openssl dgst -sha256 -mac HMAC -macopt "key:$SECUREPROMPT_BACKUP_KEY" -r \
        | cut -d' ' -f1)
    [ -n "$SP_ENC_KEY" ] && [ -n "$SP_MAC_KEY" ] || {
        echo "sp_crypto: key derivation failed" >&2; return 1; }
    export SP_ENC_KEY SP_MAC_KEY
}

# sp_seal INFILE OUTFILE -> OUTFILE = IV||ciphertext, OUTFILE.mac = HMAC(OUTFILE)
sp_seal() {
    _in=$1; _out=$2
    sp_derive_keys || return 1
    _iv=$(openssl rand -hex 16)
    printf '%s' "$_iv" | xxd -r -p > "$_out" || {
        echo "sp_crypto: failed to write IV to $_out" >&2; rm -f "$_out"; return 1; }
    if ! openssl enc -aes-256-cbc -e -K "$SP_ENC_KEY" -iv "$_iv" -in "$_in" >> "$_out"; then
        echo "sp_crypto: encryption failed for $_in" >&2; rm -f "$_out"; return 1
    fi
    # MAC over the whole sealed file (IV + ciphertext) — encrypt-then-MAC.
    if ! openssl dgst -sha256 -mac HMAC -macopt "hexkey:$SP_MAC_KEY" -r "$_out" \
        | cut -d' ' -f1 > "$_out.mac"; then
        echo "sp_crypto: MAC computation failed for $_out" >&2
        rm -f "$_out" "$_out.mac"; return 1
    fi
}

# sp_open INFILE OUTFILE -> verify INFILE.mac, then decrypt to OUTFILE.
# On MAC mismatch: error, and DO NOT write OUTFILE.
sp_open() {
    _in=$1; _out=$2
    sp_derive_keys || return 1
    if [ ! -f "$_in.mac" ]; then
        echo "sp_crypto: missing MAC file $_in.mac" >&2; return 1
    fi
    _expected=$(cat "$_in.mac")
    _actual=$(openssl dgst -sha256 -mac HMAC -macopt "hexkey:$SP_MAC_KEY" -r "$_in" \
        | cut -d' ' -f1)
    # Plain string compare — acceptable here: local file MAC, no networked
    # timing oracle. (NOT a constant-time compare; do not claim otherwise.)
    if [ "$_expected" != "$_actual" ]; then
        echo "sp_crypto: HMAC verification FAILED for $_in — refusing to decrypt" >&2
        return 1
    fi
    # IV = first 16 bytes; body = byte 17 onward. tail -c is efficient on
    # large files (dd bs=1 would read a GB dump one byte at a time).
    _iv=$(dd if="$_in" bs=16 count=1 2>/dev/null | xxd -p -c256)
    _tmp="$_out.part"
    if tail -c +17 "$_in" \
        | openssl enc -aes-256-cbc -d -K "$SP_ENC_KEY" -iv "$_iv" > "$_tmp"; then
        mv "$_tmp" "$_out"
    else
        rm -f "$_tmp"
        echo "sp_crypto: decryption failed for $_in" >&2; return 1
    fi
}
