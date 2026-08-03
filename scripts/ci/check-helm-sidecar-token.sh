#!/usr/bin/env bash
#
# check-helm-sidecar-token.sh — MR1 review C4.
#
# WHY THIS IS A CI STEP AND NOT A CODE REVIEW
# -------------------------------------------
# C4 was recorded as SOUND on the reviewer's first pass and then withdrawn.
# The note is worth keeping:
#
#   "I confirmed the env var exists in all four deployment templates and
#    stopped there; I did not check the enclosing `{{- if .Values.license.
#    enabled }}` or render the chart. `grep` found the line; `helm template`
#    found the defect."
#
# `grep` cannot see a conditional. Only a render can. So the property is
# asserted here, by rendering, in every mode the chart supports.
#
# WHAT IT ASSERTS
#
#   Every Deployment that talks to the ML sidecar carries
#   ML_SIDECAR_INTERNAL_TOKEN, in BOTH `license.enabled` modes.
#
#   api    — gateway; POSTs /internal/model-key and every /detect call.
#   ml     — the sidecar itself; `secureprompt-ml/app/main.py` raises
#            RuntimeError AT IMPORT when the var is unset, so a tokenless pod
#            crash-loops before it can serve /health.
#   web    — the dashboard's same-origin ML proxy attaches it.
#   worker — background scan/index tasks call the sidecar directly.
#
# WHAT THE DEFECT COST, measured at `helm template sp helm/secureprompt`
# with the chart default `license.enabled: false` (values.yaml:231):
#
#     sp-secureprompt-api     token=NO
#     sp-secureprompt-ml      token=NO   <- crash-loops at import
#     sp-secureprompt-web     token=yes
#     sp-secureprompt-worker  token=yes
#
# ...and 4/4 with `--set license.enabled=true`. The token blocks in
# `api-deployment.yaml` and `ml-deployment.yaml` sat inside
# `{{- if .Values.license.enabled }}`. So on a DEFAULT `helm install` the
# sidecar crash-looped and the gateway — `secureprompt-common/src/config.rs:81`
# is `unwrap_or_default()` — sent `Authorization: Bearer ` and 401ed forever.
# With WS2-3's fail-closed `SidecarUnavailablePolicy::Block` default, that is a
# 503 on every gateway request.
#
# The secret itself is generated UNCONDITIONALLY (`templates/secrets.yaml:23`
# and `:86`), so nothing but the template gating was ever missing.
#
# Docker Compose was never affected: all five services use
# `${ML_SIDECAR_INTERNAL_TOKEN:?...}`, which is the right pattern.
set -uo pipefail

cd "$(dirname "$0")/../.."

if ! command -v helm >/dev/null 2>&1; then
    echo "ERROR: helm is not on PATH — this check cannot be skipped silently." >&2
    exit 2
fi

CHART="helm/secureprompt"
# Deployment name suffixes that MUST carry the token, in every mode.
NEEDS_TOKEN=(api ml web worker)
FAIL=0

check_mode() {
    local label="$1"; shift
    local rendered
    rendered="$(helm template sp "$CHART" "$@" 2>/dev/null)"
    if [ -z "$rendered" ]; then
        echo "ERROR: [$label] helm template produced nothing." >&2
        FAIL=1
        return
    fi

    # One line per Deployment: "<name> <yes|no>".
    local table
    table="$(printf '%s\n' "$rendered" | awk '
        function flush() {
            if (kind == "Deployment" && name != "") print name, (tok ? "yes" : "no")
        }
        /^---/                { flush(); kind = ""; name = ""; tok = 0; next }
        /^kind: Deployment$/  { kind = "Deployment"; next }
        /^  name: / && kind == "Deployment" && name == "" { name = $2; next }
        /ML_SIDECAR_INTERNAL_TOKEN/ && kind == "Deployment" { tok = 1 }
        END { flush() }
    ')"

    local missing=""
    for suffix in "${NEEDS_TOKEN[@]}"; do
        local line
        line="$(printf '%s\n' "$table" | grep -E "^sp-secureprompt-${suffix} " || true)"
        if [ -z "$line" ]; then
            missing="${missing}
       the ${suffix} Deployment did not render at all — this check cannot vouch for a workload that is not there."
        elif [ "${line##* }" != "yes" ]; then
            missing="${missing}
       ${suffix}: no ML_SIDECAR_INTERNAL_TOKEN. The sidecar raises RuntimeError at import without it and the gateway sends an empty Bearer; with the fail-closed sidecar default that is 503 on every request."
        fi
    done

    if [ -n "$missing" ]; then
        echo "ERROR: [$label]${missing}" >&2
        FAIL=1
    else
        echo "  ok  [$label] — api, ml, web, worker all carry ML_SIDECAR_INTERNAL_TOKEN"
    fi
}

# The FIRST of these is the one that mattered: it is the chart default, and it
# is the mode nobody rendered.
check_mode "defaults (license.enabled=false)"
check_mode "license enabled"                 --set license.enabled=true
check_mode "scaled out"                      --set api.replicaCount=3 --set worker.replicaCount=2
if [ -f "$CHART/values-airgap.yaml" ]; then
    check_mode "airgap"                      -f "$CHART/values-airgap.yaml"
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

echo "helm render OK: the ML sidecar token reaches api, ml, web and worker in every mode."
