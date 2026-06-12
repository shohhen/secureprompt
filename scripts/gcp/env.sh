#!/usr/bin/env bash
# Shared env for all scripts/gcp/* scripts. Source this file: `source scripts/gcp/env.sh`.
set -euo pipefail

export PROJECT_ID="${PROJECT_ID:-secure-prompt-496204}"
export REGION="${REGION:-us-central1}"
export ZONE="${ZONE:-us-central1-a}"

export AR_REPO="${AR_REPO:-secureprompt}"
export AR_HOST="${REGION}-docker.pkg.dev"
export IMAGE_PREFIX="${AR_HOST}/${PROJECT_ID}/${AR_REPO}"

export CLUSTER_NAME="${CLUSTER_NAME:-secureprompt-demo}"
export NODE_MACHINE_TYPE="${NODE_MACHINE_TYPE:-e2-standard-4}"
export NODE_COUNT="${NODE_COUNT:-1}"
# Spot node = ~70% cheaper compute (can be reclaimed with 30s notice; fine for a
# demo). Set SPOT="" to use a normal on-demand node instead.
export SPOT="${SPOT:-1}"
export DISK_SIZE_GB="${DISK_SIZE_GB:-50}"

export RELEASE="${RELEASE:-secureprompt}"
export NAMESPACE="${NAMESPACE:-secureprompt}"
export DOMAIN="${DOMAIN:-secureprompt.tech}"

export IMAGE_TAG="${IMAGE_TAG:-0.1.0}"
# web is at 0.1.1: the client bundle now bakes NEXT_PUBLIC_API_URL at build time
# (0.1.0 shipped with http://localhost:8080 hardcoded → browser API calls failed).
export WEB_IMAGE_TAG="${WEB_IMAGE_TAG:-0.1.1}"

# Public API origin baked into the web client bundle at build time (NEXT_PUBLIC_*
# is inlined by Next.js at build, not runtime).
export NEXT_PUBLIC_API_URL="${NEXT_PUBLIC_API_URL:-https://api.${DOMAIN}}"
