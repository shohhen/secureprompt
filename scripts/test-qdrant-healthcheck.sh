#!/usr/bin/env bash
# Regression test: verify the Qdrant healthcheck command works inside the
# qdrant/qdrant image before relying on it in docker-compose.
#
# Root cause: qdrant/qdrant:v1.17.1 ships bash but NOT wget or curl.
# The healthcheck must use bash TCP redirection, not wget/curl.
#
# Usage: ./scripts/test-qdrant-healthcheck.sh
# Requires: Docker daemon running.

set -euo pipefail

IMAGE="qdrant/qdrant:v1.17.1"
CONTAINER="qdrant-hc-test-$$"

echo "=== Qdrant healthcheck regression test ==="
echo "Image: $IMAGE"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Start a temporary Qdrant container
docker run -d --name "$CONTAINER" -p 16333:6333 "$IMAGE" >/dev/null
echo "Container started: $CONTAINER"

# Wait up to 10s for Qdrant to bind its port
for i in $(seq 1 10); do
  if docker exec "$CONTAINER" bash -c "echo > /dev/tcp/localhost/6333" 2>/dev/null; then
    echo "Port open after ${i}s"
    break
  fi
  sleep 1
done

# --- Test 1: bash TCP check (the one we use in docker-compose) ---
echo -n "Test 1 — bash TCP healthcheck: "
if docker exec "$CONTAINER" bash -c "echo > /dev/tcp/localhost/6333"; then
  echo "PASS"
else
  echo "FAIL — bash /dev/tcp check failed"
  exit 1
fi

# --- Test 2: wget must NOT be present (so we don't silently revert) ---
echo -n "Test 2 — wget absent from image: "
if docker exec "$CONTAINER" bash -c "which wget" 2>/dev/null; then
  echo "WARN — wget is now available; consider switching to: wget -qO- http://localhost:6333/healthz"
else
  echo "PASS (wget not found, bash TCP check is correct)"
fi

# --- Test 3: curl must NOT be present ---
echo -n "Test 3 — curl absent from image: "
if docker exec "$CONTAINER" bash -c "which curl" 2>/dev/null; then
  echo "WARN — curl is now available; consider switching to: curl -sf http://localhost:6333/healthz"
else
  echo "PASS (curl not found, bash TCP check is correct)"
fi

echo ""
echo "All tests passed. docker-compose healthcheck is correct for $IMAGE."
