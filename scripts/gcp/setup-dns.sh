#!/usr/bin/env bash
# Create A records in Cloud DNS pointing apex + app + api at the Ingress LB.
# Run AFTER the Ingress has an IP (kubectl -n secureprompt get ingress).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

ZONE_NAME="${ZONE_NAME:-secureprompt-tech}"
DNS_NAME="${DOMAIN}."

echo "==> Ensuring Cloud DNS managed zone '${ZONE_NAME}' for ${DNS_NAME}…"
if ! gcloud dns managed-zones describe "${ZONE_NAME}" >/dev/null 2>&1; then
  gcloud dns managed-zones create "${ZONE_NAME}" \
    --dns-name="${DNS_NAME}" \
    --description="SecurePrompt"
fi

echo
echo "==> Cloud DNS nameservers for ${DOMAIN} — set these at your registrar:"
gcloud dns managed-zones describe "${ZONE_NAME}" --format="value(nameServers)" | tr ';' '\n' | sed 's/^/    /'

# Get LB IP from Ingress.
IP="$(kubectl -n "${NAMESPACE}" get ingress "${RELEASE}" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
if [[ -z "${IP}" ]]; then
  echo
  echo "!! Ingress has no IP yet. Re-run this script once 'kubectl -n ${NAMESPACE} get ingress' shows an ADDRESS."
  exit 1
fi
echo
echo "==> Ingress IP: ${IP}"

upsert_a() {
  local host="$1"
  local fqdn="${host}.${DNS_NAME}"
  if [[ "${host}" == "@" ]]; then fqdn="${DNS_NAME}"; fi

  echo "==> Upserting A ${fqdn} -> ${IP}"
  local tx
  tx="$(mktemp -d)"
  trap 'rm -rf "${tx}"' RETURN

  gcloud dns record-sets transaction start --zone="${ZONE_NAME}" --transaction-file="${tx}/tx.yaml" >/dev/null

  # If a record exists, remove it first (need the current value).
  local existing
  existing="$(gcloud dns record-sets list --zone="${ZONE_NAME}" --name="${fqdn}" --type=A --format='value(rrdatas[0])' 2>/dev/null || true)"
  if [[ -n "${existing}" ]]; then
    gcloud dns record-sets transaction remove --zone="${ZONE_NAME}" --transaction-file="${tx}/tx.yaml" \
      --name="${fqdn}" --type=A --ttl=300 "${existing}" >/dev/null
  fi
  gcloud dns record-sets transaction add --zone="${ZONE_NAME}" --transaction-file="${tx}/tx.yaml" \
    --name="${fqdn}" --type=A --ttl=300 "${IP}" >/dev/null
  gcloud dns record-sets transaction execute --zone="${ZONE_NAME}" --transaction-file="${tx}/tx.yaml" >/dev/null
}

upsert_a "@"
upsert_a "app"
upsert_a "api"

echo
echo "==> DNS records created. Allow up to ~15 min for propagation."
echo "    Verify: dig +short app.${DOMAIN}  ->  ${IP}"
