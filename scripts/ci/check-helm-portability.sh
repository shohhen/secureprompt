#!/usr/bin/env bash
#
# check-helm-portability.sh — WS6-5.
#
# WHY THIS EXISTS
# ---------------
# The PRD demotes Helm to the SECONDARY install path and requires that
# `helm template` render on vanilla Kubernetes. It did not. Rendered at chart
# defaults on commit fb5e1df, `helm template sp helm/secureprompt` emitted:
#
#   apiVersion: networking.gke.io/v1        kind: ManagedCertificate
#   annotations: networking.gke.io/managed-certificates: sp-secureprompt-cert
#   annotations: kubernetes.io/ingress.class: "gce"
#   annotations: cloud.google.com/neg: '{"ingress": true}'   (x2 Services)
#   storageClassName: "standard-rwo"                         (x5 PVCs)
#
# None of those exist outside GKE:
#   * ManagedCertificate is a GKE CRD. `kubectl apply` on any other cluster
#     fails the whole release with `no matches for kind "ManagedCertificate"`.
#   * ingress.class "gce" names the GKE ingress controller. On a cluster
#     running ingress-nginx nothing claims the Ingress and it never gets an
#     address.
#   * cloud.google.com/neg is a GKE network-endpoint-group hint. Inert
#     elsewhere, but it advertises the wrong platform.
#   * standard-rwo is GKE's PD-balanced StorageClass. Elsewhere the PVCs stay
#     Pending forever and every pod stays in ContainerCreating.
#
# The airgap values file — the one an on-prem bank actually installs — carried
# every one of those too, because it overrides images and nothing else.
#
# WHAT THIS ASSERTS
#   1. In each PORTABLE render mode, no GKE-only API group, annotation, or
#      StorageClass name appears anywhere in the manifest.
#   2. POSITIVE CONTROL: with -f values-gke.yaml the GKE artifacts DO appear.
#      Without this the check would also pass against a chart that renders
#      nothing at all, or one where someone deleted the ingress template.
#   3. PREMISE: every mode renders a non-empty manifest containing the api
#      Deployment. A `helm template` that silently produced nothing would
#      otherwise satisfy (1) vacuously.
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

# Patterns that must NOT appear in a portable render. Extended-regex, matched
# against the rendered text.
GKE_ONLY_RE='networking\.gke\.io|cloud\.google\.com/|kubernetes\.io/ingress\.class:[[:space:]]*"?gce|standard-rwo'

render() {
    helm template sp "$CHART" "$@" 2>/dev/null
}

# PREMISE — a mode that renders nothing satisfies every "must not contain"
# assertion for free. Refuse to draw a conclusion from an empty manifest.
premise_ok() {
    local label="$1" rendered="$2"
    if [ -z "$rendered" ]; then
        echo "ERROR: [$label] helm template produced nothing — no conclusion can be drawn." >&2
        return 1
    fi
    # `printf ... | grep -q` is NOT usable here: grep -q exits on the first
    # match, printf takes SIGPIPE, and `set -o pipefail` then reports 141 for a
    # pipeline that SUCCEEDED. That is not a hypothetical -- it is how this
    # check first went red against four modes that render perfectly well.
    if ! grep -q '^  name: sp-secureprompt-api$' <<<"$rendered"; then
        echo "ERROR: [$label] the api Deployment did not render; this check would pass vacuously." >&2
        return 1
    fi
    return 0
}

check_portable() {
    local label="$1"; shift
    local rendered hits
    rendered="$(render "$@")"
    premise_ok "$label" "$rendered" || { FAIL=1; return; }

    hits="$(grep -nE "$GKE_ONLY_RE" <<<"$rendered" || true)"
    if [ -n "$hits" ]; then
        echo "ERROR: [$label] GKE-only constructs in a render that must work on vanilla Kubernetes:" >&2
        printf '%s\n' "$hits" | sed 's/^/       /' >&2
        FAIL=1
    else
        echo "  ok  [$label] — no GKE-only API group, annotation or StorageClass"
    fi
}

# POSITIVE CONTROL. The GKE overlay must still produce the GKE artifacts. If
# this goes quiet the portable assertions above stopped meaning anything.
check_gke_control() {
    local rendered
    if [ ! -f "$CHART/values-gke.yaml" ]; then
        echo "ERROR: [positive control] $CHART/values-gke.yaml is missing — the GKE path must stay expressible." >&2
        FAIL=1
        return
    fi
    rendered="$(render -f "$CHART/values-gke.yaml")"
    premise_ok "positive control (values-gke.yaml)" "$rendered" || { FAIL=1; return; }

    local missing=""
    for needle in 'networking.gke.io/v1' 'kind: ManagedCertificate' 'cloud.google.com/neg'; do
        grep -qF "$needle" <<<"$rendered" || missing="$missing $needle"
    done
    if [ -n "$missing" ]; then
        echo "ERROR: [positive control] values-gke.yaml no longer renders:$missing" >&2
        echo "       The portable assertions cannot be trusted while the control is silent." >&2
        FAIL=1
    else
        echo "  ok  [positive control] — values-gke.yaml still renders ManagedCertificate + neg annotations"
    fi
}

# The modes a portable install has to survive. The airgap one is the mode an
# on-prem bank installs, and it was as GKE-bound as the default.
check_portable "defaults"
check_portable "license enabled"   --set license.enabled=true
check_portable "airgap"            -f "$CHART/values-airgap.yaml"
check_portable "HA (replicas>1)"   --set api.replicaCount=3 --set worker.replicaCount=2
check_portable "librechat enabled" --set librechat.enabled=true
check_gke_control

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
echo "helm portability OK: every portable mode renders GKE-free; the GKE overlay still renders GKE."
