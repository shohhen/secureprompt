#!/usr/bin/env bash
# Bootstrap GCP project for a SecurePrompt GKE demo deploy.
# Idempotent: safe to re-run.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

echo "==> Using project: ${PROJECT_ID} (region ${REGION}, zone ${ZONE})"
gcloud config set project "${PROJECT_ID}" >/dev/null

echo "==> Enabling required APIs (one-time, idempotent)…"
gcloud services enable \
  container.googleapis.com \
  artifactregistry.googleapis.com \
  compute.googleapis.com \
  dns.googleapis.com \
  cloudbuild.googleapis.com \
  --quiet

echo "==> Ensuring Artifact Registry repo '${AR_REPO}' exists in ${REGION}…"
if ! gcloud artifacts repositories describe "${AR_REPO}" --location="${REGION}" >/dev/null 2>&1; then
  gcloud artifacts repositories create "${AR_REPO}" \
    --repository-format=docker \
    --location="${REGION}" \
    --description="SecurePrompt container images"
else
  echo "    repo already exists"
fi

echo "==> Configuring docker auth for ${AR_HOST}…"
gcloud auth configure-docker "${AR_HOST}" --quiet

echo "==> Ensuring GKE cluster '${CLUSTER_NAME}' exists in ${ZONE}…"
if ! gcloud container clusters describe "${CLUSTER_NAME}" --zone="${ZONE}" >/dev/null 2>&1; then
  gcloud container clusters create "${CLUSTER_NAME}" \
    --zone="${ZONE}" \
    --num-nodes="${NODE_COUNT}" \
    --machine-type="${NODE_MACHINE_TYPE}" \
    --disk-size="${DISK_SIZE_GB}" \
    --disk-type=pd-standard \
    --release-channel=regular \
    --enable-ip-alias \
    --no-enable-master-authorized-networks \
    --addons=HttpLoadBalancing,HorizontalPodAutoscaling \
    --workload-pool="${PROJECT_ID}.svc.id.goog" \
    ${SPOT:+--spot}
else
  echo "    cluster already exists"
fi

# GKE nodes run as the default compute service account, which does NOT have
# permission to pull from Artifact Registry by default — fresh deploys hit a 403
# (ImagePullBackOff) without this grant. Scope it to the repo, idempotent.
echo "==> Granting Artifact Registry reader to the node service account…"
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
NODE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
gcloud artifacts repositories add-iam-policy-binding "${AR_REPO}" \
  --location="${REGION}" \
  --member="serviceAccount:${NODE_SA}" \
  --role="roles/artifactregistry.reader" \
  --quiet >/dev/null 2>&1 || echo "    (binding may already exist)"

echo "==> Fetching kubectl credentials…"
gcloud container clusters get-credentials "${CLUSTER_NAME}" --zone="${ZONE}"

echo "==> Ensuring namespace '${NAMESPACE}' exists…"
kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}"

echo
echo "==> Bootstrap complete."
echo "    Next: scripts/gcp/build-and-push.sh   (build & push images)"
echo "          scripts/gcp/deploy.sh           (helm install)"
