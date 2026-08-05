#!/usr/bin/env bash
#
# check-pod-hardening.sh — WS6-5.
#
# WHY THIS EXISTS
# ---------------
# The PRD asks for `runAsNonRoot`, `readOnlyRootFilesystem`, NetworkPolicy and
# resource limits. Rendered at chart defaults on fb5e1df, the actual state was
# (parsed from `helm template`, not grepped):
#
#   container                  limits  runAsNonRoot  readOnlyRootFilesystem
#   api/db-migrate (init)      Y       true          true      <- the only one
#   worker/db-migrate (init)   Y       true          true      <- the only one
#   api, worker, web, ml       Y       -             -
#   postgres, clickhouse       Y       -             -
#   grafana, prometheus,
#     alertmanager             Y       -             -
#   valkey, qdrant             N       -             -   <- no resources at all
#
#   NetworkPolicy objects rendered: 0
#
# WHAT THIS ASSERTS, in every render mode
#   1. Every container (init and main) has BOTH resources.requests and
#      resources.limits, with cpu and memory in each.
#   2. Every container has a securityContext with allowPrivilegeEscalation
#      false, capabilities.drop [ALL], runAsNonRoot true and
#      readOnlyRootFilesystem true — unless it is on the exemption list below.
#   3. At least one NetworkPolicy renders, and it has a default-deny ingress
#      rule (a policy that allows everything is not a policy).
#   4. PREMISE: the manifest is non-empty and contains the api Deployment.
#   5. The exemption list may not rot: an exemption naming a container that no
#      longer renders is an error, so a removed workload cannot leave a
#      permanent hole behind it.
#
# WHY THE EXEMPTIONS ARE WHERE THEY ARE — each was MEASURED with `docker run`
# against the exact pinned image, not reasoned about. See the report for the
# transcripts; the one-line results are in EXEMPT_REASONS below.
set -uo pipefail

cd "$(dirname "$0")/../.."

if ! command -v helm >/dev/null 2>&1; then
    echo "ERROR: helm is not on PATH — this check cannot be skipped silently." >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is not on PATH — this check parses rendered YAML, it does not grep it." >&2
    exit 2
fi

CHART="helm/secureprompt"
FAIL=0

run_mode() {
    local label="$1"; shift
    local rendered
    rendered="$(helm template sp "$CHART" "$@" 2>/dev/null)"
    if [ -z "$rendered" ]; then
        echo "ERROR: [$label] helm template produced nothing — no conclusion can be drawn." >&2
        FAIL=1
        return
    fi
    if ! printf '%s\n' "$rendered" | python3 scripts/ci/pod_hardening_lib.py "$label"; then
        FAIL=1
    fi
}

run_mode "defaults"
run_mode "license enabled"   --set license.enabled=true
run_mode "airgap"            -f "$CHART/values-airgap.yaml"
run_mode "HA (replicas>1)"   --set api.replicaCount=3 --set worker.replicaCount=2
run_mode "librechat enabled" --set librechat.enabled=true
run_mode "backup enabled"    --set backup.enabled=true
if [ -f "$CHART/values-gke.yaml" ]; then
    run_mode "gke overlay"   -f "$CHART/values-gke.yaml"
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
echo "pod hardening OK in every render mode."
