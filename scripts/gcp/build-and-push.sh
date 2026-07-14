#!/usr/bin/env bash
# Build & push all SecurePrompt images for linux/amd64 to Artifact Registry.
# Uses buildx so the deploy works from any host (incl. arm64 Mac).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"
cd "${SCRIPT_DIR}/../.."

# The ml Dockerfile bakes the MODEL-KEK from this build-arg and hard-fails if it
# is empty. Source it from .env when not already exported so `build_push ml`
# succeeds (harmless build-arg for the other images).
if [[ -z "${SECUREPROMPT_PINNED_MODEL_KEK:-}" && -f .env ]]; then
  export SECUREPROMPT_PINNED_MODEL_KEK="$(grep -E '^SECUREPROMPT_PINNED_MODEL_KEK=' .env | head -1 | cut -d= -f2-)"
fi

PLATFORM="${PLATFORM:-linux/amd64}"

# Ensure a buildx builder exists for multi-arch.
if ! docker buildx inspect sp-builder >/dev/null 2>&1; then
  docker buildx create --name sp-builder --use
else
  docker buildx use sp-builder
fi
docker buildx inspect --bootstrap >/dev/null

build_push() {
  local name="$1" dockerfile="$2" context="${3:-.}" tag="${4:-${IMAGE_TAG}}"
  local image="${IMAGE_PREFIX}/${name}:${tag}"
  echo
  echo "==> Building ${name} -> ${image}"
  docker buildx build \
    --platform "${PLATFORM}" \
    --file "${dockerfile}" \
    --tag "${image}" \
    --ssh default \
    --build-arg "NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}" \
    --build-arg "SECUREPROMPT_PINNED_MODEL_KEK=${SECUREPROMPT_PINNED_MODEL_KEK:-}" \
    --push \
    "${context}"
}

# Only the images whose source changed this release are rebuilt; worker (no
# changes) and librechat (chat-only JS tweak) are re-tagged 0.1.0->0.3.0 in AR
# out-of-band to avoid re-pushing multi-GB layers over a slow link. Small images
# first so ml's large incremental push is last.
build_push "web"        "secureprompt-web/Dockerfile" "."  "${WEB_IMAGE_TAG}"
build_push "api"        "secureprompt-api/Dockerfile"
build_push "ml"         "secureprompt-ml/Dockerfile"
# build_push "librechat"  "secureprompt-chat/Dockerfile" "secureprompt-chat"   # re-tagged
# build_push "worker"     "secureprompt-worker/Dockerfile"                       # re-tagged

echo
echo "==> All images pushed to ${IMAGE_PREFIX}/*:${IMAGE_TAG}"
