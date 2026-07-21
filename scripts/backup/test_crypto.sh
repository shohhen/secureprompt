#!/usr/bin/env sh
# Self-test for lib_crypto.sh. Exits 0 on success, non-zero on failure.
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=/dev/null
. "$DIR/lib_crypto.sh"

export SECUREPROMPT_BACKUP_KEY="test-key-do-not-use-in-prod"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

printf 'the token vault original values\n' > "$TMP/plain"

# 1. round-trip: seal then open reproduces the plaintext exactly
sp_seal "$TMP/plain" "$TMP/sealed"
sp_open "$TMP/sealed" "$TMP/opened"
cmp -s "$TMP/plain" "$TMP/opened" || { echo "FAIL: round-trip mismatch"; exit 1; }

# 2. ciphertext is not plaintext
if cmp -s "$TMP/plain" "$TMP/sealed"; then echo "FAIL: sealed == plain"; exit 1; fi

# 3. tampering the ciphertext is detected (open must fail AND not write output)
cp "$TMP/sealed" "$TMP/tampered"
printf 'X' | dd of="$TMP/tampered" bs=1 seek=20 count=1 conv=notrunc 2>/dev/null
rm -f "$TMP/out_tampered"
if sp_open "$TMP/tampered" "$TMP/out_tampered" 2>/dev/null; then
  echo "FAIL: tampered ciphertext was accepted"; exit 1
fi
[ ! -f "$TMP/out_tampered" ] || { echo "FAIL: output written despite bad MAC"; exit 1; }

# 4. wrong key is detected (different key -> MAC mismatch)
cp "$TMP/sealed" "$TMP/s2"; cp "$TMP/sealed.mac" "$TMP/s2.mac"
export SECUREPROMPT_BACKUP_KEY="a-completely-different-key"
if sp_open "$TMP/s2" "$TMP/out_wrongkey" 2>/dev/null; then
  echo "FAIL: wrong key accepted"; exit 1
fi

# 5. enc key and mac key differ (domain separation)
export SECUREPROMPT_BACKUP_KEY="test-key-do-not-use-in-prod"
sp_derive_keys
[ "$SP_ENC_KEY" != "$SP_MAC_KEY" ] || { echo "FAIL: enc key == mac key"; exit 1; }

# 6. sp_seal fails (non-zero) and leaves NO sealed file when input is missing
rm -f "$TMP/nope.enc" "$TMP/nope.enc.mac"
if sp_seal "$TMP/does-not-exist" "$TMP/nope.enc" 2>/dev/null; then
  echo "FAIL: sp_seal returned success on missing input"; exit 1
fi
[ ! -f "$TMP/nope.enc" ] || { echo "FAIL: sealed file left behind after seal failure"; exit 1; }

# 7. tampering a byte in the IV region (first 16 bytes) is also detected
cp "$TMP/sealed" "$TMP/tampered_iv"
printf 'Z' | dd of="$TMP/tampered_iv" bs=1 seek=2 count=1 conv=notrunc 2>/dev/null
rm -f "$TMP/out_tampered_iv"
if sp_open "$TMP/tampered_iv" "$TMP/out_tampered_iv" 2>/dev/null; then
  echo "FAIL: tampered IV was accepted"; exit 1
fi
[ ! -f "$TMP/out_tampered_iv" ] || { echo "FAIL: output written despite tampered IV"; exit 1; }

echo "ALL CRYPTO TESTS PASSED"
