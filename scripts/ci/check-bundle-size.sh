#!/usr/bin/env bash
# check-bundle-size.sh — VALIDATION 5-09-02
# Asserts secureprompt/web:local image is < 300 MB (with 5% slack = 315 MB)
# and combined secureprompt/* images sum < 2 GB.
set -euo pipefail

MAX_WEB_SIZE=$((315 * 1024 * 1024))            # 300 MB + 5% slack
MAX_COMBINED_SIZE=$((2 * 1024 * 1024 * 1024))  # 2 GB

WEB_SIZE=$(docker inspect secureprompt/web:local --format '{{.Size}}' 2>/dev/null || echo 0)
if [[ "$WEB_SIZE" -eq 0 ]]; then
    echo "ERROR: secureprompt/web:local image not found. Build it first:" >&2
    echo "  docker build -f secureprompt-web/Dockerfile -t secureprompt/web:local ." >&2
    exit 1
fi

if [[ "$WEB_SIZE" -gt "$MAX_WEB_SIZE" ]]; then
    echo "ERROR: web image ${WEB_SIZE} B exceeds limit ${MAX_WEB_SIZE} B (300 MB + 5% slack)" >&2
    exit 1
fi

# Sum all secureprompt/* image sizes reported by docker images.
# docker images --format outputs human-readable sizes like "123MB", "1.5GB", "456kB".
COMBINED=$(docker images --filter reference="secureprompt/*" --format "{{.Size}}" | \
    awk '{
        n = $1
        if (/GB$/) n *= 1024 * 1024 * 1024
        else if (/MB$/) n *= 1024 * 1024
        else if (/kB$/) n *= 1024
        sum += n
    } END { printf "%d\n", sum }')

if [[ "${COMBINED:-0}" -gt "$MAX_COMBINED_SIZE" ]]; then
    echo "ERROR: combined secureprompt/* image size ${COMBINED} B exceeds 2 GB limit" >&2
    exit 1
fi

echo "bundle-size OK: web=${WEB_SIZE} B  combined=${COMBINED} B"
