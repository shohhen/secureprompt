#!/usr/bin/env bash
# Helm install / upgrade SecurePrompt into the GKE cluster.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"
cd "${SCRIPT_DIR}/../.."

# Make sure kubectl points at the right cluster (defensive).
gcloud container clusters get-credentials "${CLUSTER_NAME}" --zone="${ZONE}" >/dev/null 2>&1 || true

kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}"

# License chain (env-only): the ML image ships encrypted weights and runs with
# SECUREPROMPT_MODEL_KEY_REQUIRED=true, so the gateway must verify the compact
# license token, unwrap the sealed model key with the KEK, and push it to the
# sidecar. We carry the token + KEK (from the gitignored .env, or the ambient
# environment) into the cluster as a Secret and enable the chart's license
# wiring. Set LICENSE_ENABLED=false to skip (GLiNER-only fallback).
LICENSE_ENABLED="${LICENSE_ENABLED:-true}"
LICENSE_SECRET="${LICENSE_SECRET:-secureprompt-license}"
LICENSE_SERVER_URL="${LICENSE_SERVER_URL:-}"   # optional sp-admin /api base URL
HELM_LICENSE_ARGS=(--set license.enabled=false)
if [[ "${LICENSE_ENABLED}" == "true" ]]; then
  # Source the license material, in precedence order:
  #   1. explicit environment variables (override everything)
  #   2. the canonical files in etc/secureprompt/ — license.json holds the
  #      compact token; keys.json holds { kek, vendor_pubkey } (base64). These
  #      are the values whose unwrapped model key matches the encrypted weights
  #      shipped in the ml image. (A mismatched token/KEK unwraps to the wrong
  #      key and the sidecar fails to decrypt the XLM-R weights — GCM InvalidTag.)
  #   3. .env (local dev fallback)
  LICENSE_DIR="${LICENSE_DIR:-etc/secureprompt}"
  LIC_TOKEN="${SECUREPROMPT_LICENSE_TOKEN:-}"
  LIC_KEK="${SECUREPROMPT_MODEL_KEK:-}"
  LIC_PUBKEY="${SECUREPROMPT_LICENSE_PUBKEY:-}"
  if command -v python3 >/dev/null 2>&1 \
     && [[ -f "${LICENSE_DIR}/license.json" && -f "${LICENSE_DIR}/keys.json" ]]; then
    # license.json may be a raw token or JSON wrapping one; pull the compact
    # `base64url.base64url` token out either way. kek/vendor_pubkey come from
    # keys.json. Emitted one-per-line so values containing +/=/ stay intact.
    # bash 3.2 (macOS default) has no `mapfile`; read the 3 lines individually.
    { IFS= read -r _F_TOK; IFS= read -r _F_KEK; IFS= read -r _F_PUB; } < <(python3 - "${LICENSE_DIR}" <<'PY'
import sys, re, json, pathlib
d = pathlib.Path(sys.argv[1])
raw = (d / "license.json").read_text()
m = re.search(r'[A-Za-z0-9_\-]{40,}\.[A-Za-z0-9_\-]{40,}', raw)
kj = json.load(open(d / "keys.json"))
print(m.group(0) if m else "")
print(kj.get("kek", ""))
print(kj.get("vendor_pubkey", ""))
PY
)
    [[ -z "${LIC_TOKEN}"  ]] && LIC_TOKEN="${_F_TOK:-}"
    [[ -z "${LIC_KEK}"    ]] && LIC_KEK="${_F_KEK:-}"
    [[ -z "${LIC_PUBKEY}" ]] && LIC_PUBKEY="${_F_PUB:-}"
  fi
  if [[ -f .env ]]; then
    [[ -z "${LIC_TOKEN}"  ]] && LIC_TOKEN="$(grep -E '^SECUREPROMPT_LICENSE_TOKEN=' .env | head -1 | cut -d= -f2-)"
    [[ -z "${LIC_KEK}"    ]] && LIC_KEK="$(grep -E '^SECUREPROMPT_MODEL_KEK=' .env | head -1 | cut -d= -f2-)"
    [[ -z "${LIC_PUBKEY}" ]] && LIC_PUBKEY="$(grep -E '^SECUREPROMPT_LICENSE_PUBKEY=' .env | head -1 | cut -d= -f2-)"
  fi
  if [[ -n "${LIC_TOKEN}" && -n "${LIC_KEK}" && -n "${LIC_PUBKEY}" ]]; then
    echo "==> Creating/refreshing license secret '${LICENSE_SECRET}' (env-only token + KEK + pubkey)"
    kubectl -n "${NAMESPACE}" create secret generic "${LICENSE_SECRET}" \
      --from-literal=license-token="${LIC_TOKEN}" \
      --from-literal=model-kek="${LIC_KEK}" \
      --from-literal=license-pubkey="${LIC_PUBKEY}" \
      --dry-run=client -o yaml | kubectl -n "${NAMESPACE}" apply -f -
    HELM_LICENSE_ARGS=(--set license.enabled=true --set "license.secretName=${LICENSE_SECRET}")
    [[ -n "${LICENSE_SERVER_URL}" ]] && HELM_LICENSE_ARGS+=(--set "license.serverUrl=${LICENSE_SERVER_URL}")
  else
    echo "!! LICENSE_ENABLED=true but SECUREPROMPT_LICENSE_TOKEN / SECUREPROMPT_MODEL_KEK /"
    echo "   SECUREPROMPT_LICENSE_PUBKEY not all found in the environment or .env. Provide"
    echo "   them, or set LICENSE_ENABLED=false to deploy GLiNER-only."
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
