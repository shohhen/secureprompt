#!/usr/bin/env bash
# Build & push all SecurePrompt images for linux/amd64 to Artifact Registry.
# Uses buildx so the deploy works from any host (incl. arm64 Mac).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"
cd "${SCRIPT_DIR}/../.."

PLATFORM="${PLATFORM:-linux/amd64}"

# Ensure a buildx builder exists for multi-arch.
if ! docker buildx inspect sp-builder >/dev/null 2>&1; then
  docker buildx create --name sp-builder --use
else
  docker buildx use sp-builder
fi
docker buildx inspect --bootstrap >/dev/null

build_push() {
  local name="$1" dockerfile="$2" context="${3:-.}"
  local image="${IMAGE_PREFIX}/${name}:${IMAGE_TAG}"
  echo
  echo "==> Building ${name} -> ${image}"
  docker buildx build \
    --platform "${PLATFORM}" \
    --file "${dockerfile}" \
    --tag "${image}" \
    --ssh default \
    --build-arg "NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}" \
    --push \
    "${context}"
}

# Order matters only for caching speed; everything is independent.
build_push "librechat"  "secureprompt-chat/Dockerfile" "secureprompt-chat"
build_push "marketing"  "secureprompt-marketing/Dockerfile"
build_push "web"        "secureprompt-web/Dockerfile"
build_push "ml"         "secureprompt-ml/Dockerfile"
build_push "api"        "secureprompt-api/Dockerfile"
build_push "worker"     "secureprompt-worker/Dockerfile"

echo
echo "==> All images pushed to ${IMAGE_PREFIX}/*:${IMAGE_TAG}"
