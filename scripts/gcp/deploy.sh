#!/usr/bin/env bash
# Helm install / upgrade SecurePrompt into the GKE cluster.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"
cd "${SCRIPT_DIR}/../.."

# Make sure kubectl points at the right cluster (defensive).
gcloud container clusters get-credentials "${CLUSTER_NAME}" --zone="${ZONE}" >/dev/null 2>&1 || true

kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}"

# License chain: the ML image ships encrypted weights and runs with
# SECUREPROMPT_MODEL_KEY_REQUIRED=true, so the gateway must read license.json +
# keys.json, unwrap the sealed model key, and push it to the sidecar. We carry
# those two gitignored files into the cluster as a Secret and enable the chart's
# license wiring. Set LICENSE_ENABLED=false to skip (GLiNER-only fallback).
LICENSE_ENABLED="${LICENSE_ENABLED:-true}"
LICENSE_SECRET="${LICENSE_SECRET:-secureprompt-license}"
LICENSE_DIR="${LICENSE_DIR:-etc/secureprompt}"
HELM_LICENSE_ARGS=(--set license.enabled=false)
if [[ "${LICENSE_ENABLED}" == "true" ]]; then
  if [[ -f "${LICENSE_DIR}/license.json" && -f "${LICENSE_DIR}/keys.json" ]]; then
    echo "==> Creating/refreshing license secret '${LICENSE_SECRET}' from ${LICENSE_DIR}/"
    kubectl -n "${NAMESPACE}" create secret generic "${LICENSE_SECRET}" \
      --from-file=license.json="${LICENSE_DIR}/license.json" \
      --from-file=keys.json="${LICENSE_DIR}/keys.json" \
      --dry-run=client -o yaml | kubectl -n "${NAMESPACE}" apply -f -
    HELM_LICENSE_ARGS=(--set license.enabled=true --set "license.filesSecret=${LICENSE_SECRET}")
  else
    echo "!! LICENSE_ENABLED=true but ${LICENSE_DIR}/{license.json,keys.json} not found."
    echo "   Provide them, or set LICENSE_ENABLED=false to deploy GLiNER-only."
    exit 1
  fi
fi

# TLS: if a Cloudflare Origin cert/key pair is provided, install it as a
# kubernetes.io/tls secret and switch the ingress to it (disabling the GCP
# managed cert). This is required when fronting the LB with the Cloudflare proxy
# (orange cloud) in Full (strict) mode. Otherwise keep the GCP managed cert.
TLS_SECRET="${TLS_SECRET:-secureprompt-tls}"
TLS_CERT_FILE="${TLS_CERT_FILE:-secrets/cf-origin.crt}"
TLS_KEY_FILE="${TLS_KEY_FILE:-secrets/cf-origin.key}"
HELM_TLS_ARGS=()
if [[ -f "${TLS_CERT_FILE}" && -f "${TLS_KEY_FILE}" ]]; then
  echo "==> Installing TLS secret '${TLS_SECRET}' from ${TLS_CERT_FILE} (Cloudflare Origin cert)"
  kubectl -n "${NAMESPACE}" create secret tls "${TLS_SECRET}" \
    --cert="${TLS_CERT_FILE}" --key="${TLS_KEY_FILE}" \
    --dry-run=client -o yaml | kubectl -n "${NAMESPACE}" apply -f -
  HELM_TLS_ARGS=(--set ingress.managedCertificate.enabled=false --set "ingress.tlsSecret=${TLS_SECRET}")
fi

# LibreChat: opt-in browser chat UI (set LIBRECHAT_ENABLED=true). Generates its
# stable JWT/creds secrets once (idempotent — only created if missing, so they
# survive redeploys; CREDS_KEY must be 64 hex / CREDS_IV 32 hex for LibreChat).
LIBRECHAT_ENABLED="${LIBRECHAT_ENABLED:-false}"
HELM_LIBRECHAT_ARGS=(--set librechat.enabled=false)
if [[ "${LIBRECHAT_ENABLED}" == "true" ]]; then
  if ! kubectl -n "${NAMESPACE}" get secret secureprompt-librechat-secrets >/dev/null 2>&1; then
    echo "==> Generating LibreChat secrets (one-time)"
    kubectl -n "${NAMESPACE}" create secret generic secureprompt-librechat-secrets \
      --from-literal=jwt-secret="$(openssl rand -hex 32)" \
      --from-literal=jwt-refresh-secret="$(openssl rand -hex 32)" \
      --from-literal=creds-key="$(openssl rand -hex 32)" \
      --from-literal=creds-iv="$(openssl rand -hex 16)"
  fi
  HELM_LIBRECHAT_ARGS=(--set librechat.enabled=true \
    --set "librechat.image.repository=${IMAGE_PREFIX}/librechat" \
    --set "librechat.image.tag=${IMAGE_TAG}")
fi

# Image wiring: every chart template renders `{{ global.imageRegistry }}{{ repo }}`.
# We keep global.imageRegistry empty and point each of OUR 4 app images at its
# full Artifact Registry path; the data-store images (postgres, valkey, etc.)
# keep their public repos and pull from Docker Hub. (Setting global.imageRegistry
# to the AR repo would both double-prefix the app repos and wrongly route the
# public images into AR.)
echo "==> Helm upgrade --install ${RELEASE} (ns=${NAMESPACE})"
helm upgrade --install "${RELEASE}" helm/secureprompt \
  --namespace "${NAMESPACE}" \
  --create-namespace \
  --set global.imageRegistry="" \
  --set api.image.repository="${IMAGE_PREFIX}/api"             --set api.image.tag="${IMAGE_TAG}" \
  --set worker.image.repository="${IMAGE_PREFIX}/worker"       --set worker.image.tag="${IMAGE_TAG}" \
  --set web.image.repository="${IMAGE_PREFIX}/web"             --set web.image.tag="${WEB_IMAGE_TAG:-${IMAGE_TAG}}" \
  --set ml.image.repository="${IMAGE_PREFIX}/ml"               --set ml.image.tag="${IMAGE_TAG}" \
  --set ingress.domain="${DOMAIN}" \
  "${HELM_LICENSE_ARGS[@]}" \
  "${HELM_LIBRECHAT_ARGS[@]}" \
  ${HELM_TLS_ARGS[@]+"${HELM_TLS_ARGS[@]}"} \
  --wait --timeout 15m || {
    echo
    echo "!! helm upgrade timed out or failed. Pod status:"
    kubectl -n "${NAMESPACE}" get pods
    exit 1
  }

echo
echo "==> Deploy applied. Pods:"
kubectl -n "${NAMESPACE}" get pods

echo
echo "==> Ingress (LB IP may take a few minutes to appear):"
kubectl -n "${NAMESPACE}" get ingress

echo
echo "==> ManagedCertificate status (Provisioning -> Active can take 15-60 min after DNS resolves):"
kubectl -n "${NAMESPACE}" get managedcertificate
