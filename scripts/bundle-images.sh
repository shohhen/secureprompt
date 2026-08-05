#!/usr/bin/env bash
#
# bundle-images.sh — WS6-5. Build an offline image bundle for an air-gapped
# single-VM appliance install.
#
# WHAT THIS PRODUCES
#   dist/secureprompt-images-<version>/
#     images/<name>.tar        one `docker save` per image
#     manifest.tsv             image ref, tar name, size, sha256 of the tar
#     SHA256SUMS               checksums for every file above
#     load.sh                  runs on the air-gapped host: verify + docker load
#
# WHY A DIRECTORY OF PER-IMAGE TARS AND NOT ONE BIG ONE
#   `docker save a b c > all.tar` is a single ~14 GB file. On the media that
#   actually crosses an air gap (a courier'd USB disk, a one-way file diode, a
#   ticketed transfer) a corrupt or truncated multi-gigabyte blob costs the
#   whole trip. Per-image tars mean a bad transfer costs one image, and the
#   manifest says which.
#
# THE ML IMAGE IS DIFFERENT, AND THIS SCRIPT DOES NOT PRETEND OTHERWISE
#   secureprompt-ml is ~12.6 GB and is deliberately EXCLUDED from the CI `build`
#   stage — .gitlab-ci.yml's own "KNOWN CAVEATS" says it needs the raw model DEK
#   and plaintext weights, which are not wired into CI. So there is no registry
#   tag for CI to pull and no pipeline that ever produced this image. It has to
#   be built by hand, on a machine that holds the MODEL-KEK, with
#     docker build --build-arg SECUREPROMPT_PINNED_MODEL_KEK=<value> \
#       -f secureprompt-ml/Dockerfile -t secureprompt/ml:<version> .
#   This script therefore treats it as a FIRST-CLASS but SEPARATELY SOURCED
#   entry: it is in the image list, it is saved like everything else, and if it
#   is not present locally the script says exactly that and exits non-zero
#   rather than quietly shipping a bundle whose sidecar is missing — which is a
#   bundle that installs, comes up, and detects no PII.
#   `--skip-ml` is available for the case where the sidecar is transferred on
#   its own schedule; it is opt-in and it is logged into the manifest.
#
# USAGE
#   scripts/bundle-images.sh [--version X.Y.Z] [--out DIR] [--skip-ml]
#                            [--pull] [--platform linux/amd64]
#
#   --pull      fetch the third-party images first (needs a network; run this
#               on the staging host, not the air-gapped one).
#   --platform  what the TARGET host runs. Defaults to linux/amd64 because that
#               is what .gitlab-ci.yml builds and what the appliance VMs are;
#               saving arm64 layers from a developer laptop and carrying them to
#               an amd64 VM produces `exec format error` at `docker compose up`,
#               hours after the transfer.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${SP_VERSION:-0.1.0}"
OUT_ROOT="dist"
SKIP_ML=0
DO_PULL=0
PLATFORM="linux/amd64"

while [ $# -gt 0 ]; do
    case "$1" in
        --version)  VERSION="$2"; shift 2 ;;
        --out)      OUT_ROOT="$2"; shift 2 ;;
        --platform) PLATFORM="$2"; shift 2 ;;
        --skip-ml)  SKIP_ML=1; shift ;;
        --pull)     DO_PULL=1; shift ;;
        -h|--help)  sed -n '2,45p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# The image list. Every third-party tag here is the one pinned in
# docker-compose.yml — not "the latest of that thing". A bundle built from
# different tags than the compose file names is a bundle that loads fine and
# then pulls at `up`.
# ---------------------------------------------------------------------------
SP_IMAGES=(
    "secureprompt/api:${VERSION}"
    "secureprompt/worker:${VERSION}"
    "secureprompt/web:${VERSION}"
    "secureprompt/librechat:${VERSION}"
)
ML_IMAGE="secureprompt/ml:${VERSION}"
THIRD_PARTY=(
    "postgres:16-alpine"
    "valkey/valkey:8.1.6-alpine"
    "clickhouse/clickhouse-server:24.8"
    "qdrant/qdrant:v1.17.1"
    "grafana/grafana:11.4.0"
    "prom/prometheus:v2.55.1"
    "prom/alertmanager:v0.27.0"
    "mongo:7.0"
    "nginx:1.27-alpine"
)

BUNDLE="${OUT_ROOT}/secureprompt-images-${VERSION}"
IMAGES_DIR="${BUNDLE}/images"
MANIFEST="${BUNDLE}/manifest.tsv"

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }

# ---------------------------------------------------------------------------
# ASSERT THE COMPOSE FILE AGREES WITH THIS LIST.
#
# The failure this prevents is specific and has a long fuse: someone bumps
# `clickhouse/clickhouse-server:24.8` to `:25.3` in docker-compose.yml, this
# list still says 24.8, the bundle loads 24.8, and `docker compose up` on the
# air-gapped host tries to pull 25.3 from a registry that is not reachable. The
# install fails at the customer site, weeks after the bundle was built.
# ---------------------------------------------------------------------------
echo "==> checking the bundle list against docker-compose.yml"
drift=0
for ref in "${THIRD_PARTY[@]}"; do
    if ! grep -qF "image: ${ref}" docker-compose.yml; then
        echo "    MISMATCH: ${ref} is in this script but not in docker-compose.yml" >&2
        drift=1
    fi
done
while read -r composeref; do
    [ -z "$composeref" ] && continue
    case "$composeref" in secureprompt/*) continue ;; esac
    found=0
    for ref in "${THIRD_PARTY[@]}"; do
        [ "$ref" = "$composeref" ] && found=1 && break
    done
    if [ "$found" -eq 0 ]; then
        echo "    MISSING: docker-compose.yml runs ${composeref}, which this bundle would not carry" >&2
        drift=1
    fi
done < <(grep -oE '^\s+image: [a-z0-9][^$[:space:]]*$' docker-compose.yml | awk '{print $2}' | sort -u)
if [ "$drift" -ne 0 ]; then
    echo "ERROR: bundle list and docker-compose.yml disagree — fix one of them before shipping." >&2
    exit 1
fi
echo "    ok — every pinned compose image is in the bundle list"

if [ "$DO_PULL" -eq 1 ]; then
    echo "==> pulling third-party images for ${PLATFORM}"
    for ref in "${THIRD_PARTY[@]}"; do
        docker pull --platform "$PLATFORM" "$ref"
    done
fi

# ---------------------------------------------------------------------------
# Presence check BEFORE saving anything. A partial bundle is worse than none:
# it is discovered on the air-gapped side.
# ---------------------------------------------------------------------------
TO_SAVE=("${SP_IMAGES[@]}" "${THIRD_PARTY[@]}")
if [ "$SKIP_ML" -eq 0 ]; then
    TO_SAVE+=("$ML_IMAGE")
fi

echo "==> checking every image is present locally"
missing=()
for ref in "${TO_SAVE[@]}"; do
    docker image inspect "$ref" >/dev/null 2>&1 || missing+=("$ref")
done
if [ "${#missing[@]}" -ne 0 ]; then
    echo "ERROR: not in the local image store:" >&2
    for ref in "${missing[@]}"; do echo "         $ref" >&2; done
    for ref in "${missing[@]}"; do
        if [ "$ref" = "$ML_IMAGE" ]; then
            cat >&2 <<ML

       ${ML_IMAGE} has no CI build by design. .gitlab-ci.yml excludes
       secureprompt-ml from the \`build\` stage because it needs the raw model
       DEK, so nothing has ever pushed this tag. Build it on a machine that
       holds the MODEL-KEK:

         docker build --platform ${PLATFORM} \\
           --build-arg SECUREPROMPT_PINNED_MODEL_KEK=<value> \\
           -f secureprompt-ml/Dockerfile -t ${ML_IMAGE} .

       Or pass --skip-ml if the sidecar is being transferred separately. That
       is recorded in the manifest, because an appliance without the sidecar
       comes up healthy and detects no PII beyond the deterministic Rust floor.
ML
        fi
    done
    exit 1
fi

# ---------------------------------------------------------------------------
# Architecture check. `docker save` preserves whatever architecture is in the
# local store, and nothing downstream notices until the container runs.
# ---------------------------------------------------------------------------
want_arch="${PLATFORM##*/}"
echo "==> checking architectures against --platform ${PLATFORM}"
arch_bad=0
for ref in "${TO_SAVE[@]}"; do
    got="$(docker image inspect --format '{{.Architecture}}' "$ref")"
    if [ "$got" != "$want_arch" ]; then
        echo "    ${ref}: ${got}, wanted ${want_arch}" >&2
        arch_bad=1
    fi
done
if [ "$arch_bad" -ne 0 ]; then
    echo "ERROR: at least one image is the wrong architecture for the target host." >&2
    echo "       Loading these gives 'exec format error' at \`docker compose up\`, on the" >&2
    echo "       air-gapped side, after the transfer. Re-pull/rebuild with --platform ${PLATFORM}." >&2
    exit 1
fi
echo "    ok — all ${#TO_SAVE[@]} images are ${want_arch}"

rm -rf "$BUNDLE"
mkdir -p "$IMAGES_DIR"

: > "$MANIFEST"
printf 'image\ttar\tbytes\tsha256\n' >> "$MANIFEST"

sha_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

echo "==> saving ${#TO_SAVE[@]} images"
for ref in "${TO_SAVE[@]}"; do
    safe="$(printf '%s' "$ref" | tr '/:' '__')"
    tar="${IMAGES_DIR}/${safe}.tar"
    printf '    %-46s ' "$ref"
    docker save -o "$tar" "$ref"
    bytes="$(wc -c < "$tar" | tr -d ' ')"
    printf '%s\t%s\t%s\t%s\n' "$ref" "${safe}.tar" "$bytes" "$(sha_of "$tar")" >> "$MANIFEST"
    printf '%s bytes\n' "$bytes"
done

if [ "$SKIP_ML" -eq 1 ]; then
    printf '# NOTE\t--skip-ml was used: %s is NOT in this bundle.\t0\t-\n' "$ML_IMAGE" >> "$MANIFEST"
    echo "    NOTE: --skip-ml — the sidecar is NOT in this bundle."
fi

# load.sh — the only thing that runs on the air-gapped side.
cat > "${BUNDLE}/load.sh" <<'LOADER'
#!/usr/bin/env bash
# Load every image in this bundle into the local docker store.
#
# Verifies checksums FIRST. `docker load` on a truncated tar can succeed for the
# layers it got and leave a broken image behind, so the checksum is not a
# formality — it is the only thing standing between a bad transfer and a
# half-loaded appliance.
set -euo pipefail
cd "$(dirname "$0")"

sha_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

echo "==> verifying checksums"
fail=0
while IFS=$'\t' read -r image tar bytes sha; do
    [ "$image" = "image" ] && continue
    case "$image" in \#*) echo "    $image $tar"; continue ;; esac
    path="images/${tar}"
    if [ ! -f "$path" ]; then echo "    MISSING $path" >&2; fail=1; continue; fi
    got="$(sha_of "$path")"
    if [ "$got" != "$sha" ]; then
        echo "    CORRUPT $path" >&2
        echo "            expected $sha" >&2
        echo "            got      $got" >&2
        fail=1
    fi
done < manifest.tsv
[ "$fail" -eq 0 ] || { echo "ERROR: bundle is damaged — do not load it." >&2; exit 1; }
echo "    ok"

echo "==> loading"
while IFS=$'\t' read -r image tar bytes sha; do
    [ "$image" = "image" ] && continue
    case "$image" in \#*) continue ;; esac
    printf '    %-46s ' "$image"
    docker load -q -i "images/${tar}" >/dev/null
    docker image inspect "$image" >/dev/null 2>&1 || {
        echo "FAILED — loaded but not present under that tag" >&2; exit 1; }
    echo "ok"
done < manifest.tsv

echo
echo "All images loaded. Next:"
echo "  cp .env.example .env && ./scripts/init-env.sh --fill-missing"
echo "  docker compose -f docker-compose.yml -f docker-compose.onprem.yml up -d"
LOADER
chmod +x "${BUNDLE}/load.sh"

( cd "$BUNDLE" && \
  if command -v sha256sum >/dev/null 2>&1; then
      find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  else
      find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS
  fi )

total="$(awk -F'\t' 'NR>1 && $3 ~ /^[0-9]+$/ {s+=$3} END {print s+0}' "$MANIFEST")"
echo
echo "Bundle: ${BUNDLE}"
echo "Images: ${#TO_SAVE[@]}   Total: $(( total / 1024 / 1024 )) MiB"
echo "Transfer the whole directory, then run ./load.sh on the target host."
