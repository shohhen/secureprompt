#!/usr/bin/env bash
# check-image-budget.sh — Verify per-image compressed size budget (OPS-08, D-12).
#
# Measurement: docker save <image> | gzip | wc -c / 1048576 (MiB)
# Budgets: api<=150, worker<=150, mcp<=120, sp-agent<=10, ml<=900, web<=400 MiB
# Total cap: 2048 MiB

set -euo pipefail

FAILED=0
TOTAL_MIB=0

check_budget() {
    local img="$1"
    local budget_mib="$2"

    if ! docker image inspect "$img" > /dev/null 2>&1; then
        echo "SKIP: $img not found locally (not built or not applicable)"
        return 0
    fi

    local size_bytes
    size_bytes=$(docker save "$img" | gzip | wc -c)
    local size_mib=$(( size_bytes / 1048576 ))

    TOTAL_MIB=$(( TOTAL_MIB + size_mib ))

    if (( size_mib > budget_mib )); then
        echo "FAIL: $img = ${size_mib} MiB (budget: ${budget_mib} MiB — EXCEEDED by $(( size_mib - budget_mib )) MiB)"
        FAILED=1
    else
        echo "PASS: $img = ${size_mib} MiB (budget: ${budget_mib} MiB)"
    fi
}

echo "=== SecurePrompt Image Budget Check (OPS-08) ==="
echo "Measurement: docker save | gzip | wc -c / 1048576 (MiB)"
echo ""

check_budget secureprompt-api     150
check_budget secureprompt-worker  150
check_budget secureprompt-mcp     120
check_budget sp-agent              10
check_budget secureprompt-ml      900
check_budget secureprompt-web     400

echo ""
echo "Total estimated bundle size: ${TOTAL_MIB} MiB"

BUNDLE_CAP=2048
if (( TOTAL_MIB > BUNDLE_CAP )); then
    echo "FAIL: Total bundle ${TOTAL_MIB} MiB exceeds cap of ${BUNDLE_CAP} MiB"
    FAILED=1
else
    echo "PASS: Total bundle ${TOTAL_MIB} MiB within cap of ${BUNDLE_CAP} MiB"
fi

echo ""
if (( FAILED )); then
    echo "IMAGE BUDGET CHECK: FAILED"
    echo ""
    echo "To reduce image sizes:"
    echo "  - Rust images: multi-stage build with gcr.io/distroless/cc-debian12:nonroot runtime"
    echo "  - ML sidecar: python:3.11-slim + torch CPU-only wheel + clean pip cache in same RUN layer"
    echo "  - Web: Next.js standalone output + node:22-alpine runtime"
    exit 1
else
    echo "IMAGE BUDGET CHECK: PASSED"
fi
