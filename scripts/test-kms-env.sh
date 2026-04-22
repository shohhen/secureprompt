#!/usr/bin/env bash
# Regression test: verify KMS_FILE_KEY is present and valid in the api service
# environment before docker compose up.
#
# Root cause: KMS_FILE_KEY was missing from the docker-compose.yml api
# environment block, causing AppState::new to panic at startup.
#
# Usage: ./scripts/test-kms-env.sh [compose-file]
# Requires: docker compose v2

set -euo pipefail

COMPOSE_FILE="${1:-docker-compose.yml}"

echo "=== KMS_FILE_KEY env regression test ==="
echo "Compose file: $COMPOSE_FILE"

# --- Test 1: KMS_FILE_KEY present in api service config ---
echo -n "Test 1 — KMS_FILE_KEY defined in api service: "
if docker compose -f "$COMPOSE_FILE" config | grep -q "KMS_FILE_KEY"; then
  echo "PASS"
else
  echo "FAIL — KMS_FILE_KEY not found in resolved compose config"
  exit 1
fi

# --- Test 2: The resolved value decodes to exactly 32 bytes ---
echo -n "Test 2 — KMS_FILE_KEY decodes to 32 bytes: "
KMS_VAL=$(docker compose -f "$COMPOSE_FILE" config | grep "KMS_FILE_KEY" | awk -F': ' '{print $2}' | tr -d ' "')
DECODED_LEN=$(echo "$KMS_VAL" | python3 -c "import sys,base64; d=base64.b64decode(sys.stdin.read().strip()); print(len(d))")
if [ "$DECODED_LEN" -eq 32 ]; then
  echo "PASS (${DECODED_LEN} bytes)"
else
  echo "FAIL — expected 32 bytes, got ${DECODED_LEN}"
  exit 1
fi

# --- Test 3: Dev default is not empty ---
echo -n "Test 3 — KMS_FILE_KEY is non-empty: "
if [ -n "$KMS_VAL" ]; then
  echo "PASS"
else
  echo "FAIL — KMS_FILE_KEY resolved to empty string"
  exit 1
fi

echo ""
echo "All tests passed. KMS_FILE_KEY is correctly configured in $COMPOSE_FILE."
