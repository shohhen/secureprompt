#!/usr/bin/env bash
#
# check-helm-migration-initcontainer.sh — MR7 C1 / I2 / M3.
#
# WHY THIS IS A CI STEP AND NOT A CODE REVIEW
# -------------------------------------------
# Three of the six Criticals in the MR7 review were found by RENDERING the
# chart, not by reading it. Nothing in this repository rendered it: `helm lint`
# runs only in the manual `deploy` job, and lint does not look at container
# fields. So the properties below — the ones the whole DB role split rests on —
# were asserted in prose and never once checked by a machine.
#
# WHAT IT ASSERTS, in every mode the chart supports:
#
#   1. The owner credential (`migration-database-url`) reaches NO serving
#      container. This is the point of the split: a container that holds the
#      owner URL bypasses RLS. Rendered, not read.
#   2. The `db-migrate` initContainer never pulls with `IfNotPresent`.
#      `.Values.api.image.pullPolicy` is exactly that, on a tag values.yaml
#      itself documents as mutable, and a node-cached PRE-SPLIT image has no
#      argument parsing at all — `--migrate-only` is ignored, the API `main`
#      runs, JwtConfig::from_env fails on a container given only DATABASE_URL,
#      and the pod sits in Init:CrashLoopBackOff forever. `Never` is allowed:
#      an air-gapped install side-loads an exact image and has no registry.
#   3. The initContainer runs `--migrate-only` and nothing else.
#   4. (MR7 M2) The initContainer carries a securityContext with
#      `runAsNonRoot`, `readOnlyRootFilesystem` and `allowPrivilegeEscalation:
#      false`. It is the one container in the chart holding the OWNER/MIGRATOR
#      credential, and a writable rootfs plus an owner-role DSN in the
#      environment is how a compromised init step persists. Safe by
#      construction against this image: the runtime stage is
#      `gcr.io/distroless/cc-debian12:nonroot`.
#   5. (MR7 M2) Both Deployments carry a `checksum/secret` pod annotation.
#      Without it a `helm upgrade` that changed `app-db-password` alone updated
#      the Secret and left the pods running — the initContainer then set a NEW
#      password on `secureprompt_app` while the serving containers held
#      connections on the OLD one, which fails at the next reconnect, minutes
#      or hours later, looking like a network fault.
#
# It does NOT assert that only one Deployment carries the initContainer.
# Concurrency is handled where it actually lives: MIGRATION_STEP_LOCK_KEY in
# secureprompt-api/src/db/migrations.rs holds one advisory lock across the whole
# step, pinned by `concurrent_migration_steps_all_succeed`.
set -uo pipefail

cd "$(dirname "$0")/../.."

if ! command -v helm >/dev/null 2>&1; then
    echo "ERROR: helm is not on PATH — this check cannot be skipped silently." >&2
    exit 2
fi

CHART="helm/secureprompt"
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

    local report
    report="$(printf '%s\n' "$rendered" | awk -v label="$label" '
        # helm template emits deterministic two-space YAML. Both container
        # lists sit at the same indent under a pod spec, so tracking which one
        # we are inside is enough to tell an initContainer from a serving one.
        /^      initContainers:[[:space:]]*$/ { section = "init";    next }
        /^      containers:[[:space:]]*$/     { section = "serving"; next }
        /^(---|apiVersion:)/                  { section = "";        name = "" }

        /^        - name: / {
            name = $NF
            if (section == "init" && name == "db-migrate") { seen_migrate++ }
            pull = ""; args = ""
            next
        }

        # The owner credential must never be reachable from a serving container.
        section == "serving" && /key: migration-database-url/ {
            print "the serving container `" name "` is given migration-database-url — the OWNER role. It would bypass every RLS policy in the schema."
        }

        section == "init" && name == "db-migrate" && /^          imagePullPolicy:/ {
            pull = $2
            # Never is legitimate in an air-gapped install, where the operator
            # side-loads an exact image and there is no registry. IfNotPresent
            # is the value that silently serves a stale node-cached layer.
            if (pull != "Always" && pull != "Never") {
                print "the db-migrate initContainer has imagePullPolicy=" pull " on a mutable tag; a node-cached pre-split image ignores --migrate-only and crashloops forever."
            }
        }

        section == "init" && name == "db-migrate" && /^          args:/ {
            args = $0
            if (args !~ /--migrate-only/) {
                print "the db-migrate initContainer does not pass --migrate-only: " args
            }
        }

        # MR7 M2 — securityContext on the container that holds the owner DSN.
        # Matched at the initContainer field indent (10 spaces) so a serving
        # container cannot satisfy it, and the values are matched exactly:
        # `runAsNonRoot: false` must not count as "has a securityContext".
        section == "init" && name == "db-migrate" && /^          securityContext:/ { in_sc = 1; next }
        in_sc && /^          [a-z]/ { in_sc = 0 }
        in_sc && /^            runAsNonRoot: true$/              { sc_nonroot++ }
        in_sc && /^            readOnlyRootFilesystem: true$/    { sc_rofs++ }
        in_sc && /^            allowPrivilegeEscalation: false$/ { sc_nopriv++ }

        # MR7 M2 — the checksum annotation on the two Deployments that carry
        # the initContainer. Counted per rendered Deployment name so a single
        # annotation cannot satisfy both.
        /^  name: .*-(api|worker)$/ { deploy = $2 }
        /^        checksum\/secret: / { if (deploy != "") { checksum[deploy] = 1 } }

        END {
            if (seen_migrate == 0) {
                print "no db-migrate initContainer was rendered at all — the schema would be applied by whatever serves it, or not at all."
            }
            if (sc_nonroot < seen_migrate) {
                print "the db-migrate initContainer is missing `runAsNonRoot: true` (" sc_nonroot+0 " of " seen_migrate " rendered) — it is the only container holding the OWNER/MIGRATOR credential."
            }
            if (sc_rofs < seen_migrate) {
                print "the db-migrate initContainer is missing `readOnlyRootFilesystem: true` (" sc_rofs+0 " of " seen_migrate ")."
            }
            if (sc_nopriv < seen_migrate) {
                print "the db-migrate initContainer is missing `allowPrivilegeEscalation: false` (" sc_nopriv+0 " of " seen_migrate ")."
            }
            n_checksum = 0
            for (d in checksum) { n_checksum++ }
            if (n_checksum < 2) {
                print "only " n_checksum " of the 2 Deployments carrying the db-migrate initContainer has a checksum/secret pod annotation; a helm upgrade that rotates app-db-password would leave the other one running on the old credential until its next reconnect."
            }
        }
    ')"

    if [ -n "$report" ]; then
        echo "ERROR: [$label]" >&2
        printf '%s\n' "$report" | sed 's/^/       /' >&2
        FAIL=1
    else
        echo "  ok  [$label]"
    fi
}

check_mode "defaults"
check_mode "license enabled"   --set license.enabled=true
check_mode "scaled out"        --set api.replicaCount=3 --set worker.replicaCount=2
if [ -f "$CHART/values-airgap.yaml" ]; then
    check_mode "airgap"        -f "$CHART/values-airgap.yaml"
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

echo "helm render OK: owner credential confined to the initContainer, which never pulls IfNotPresent, runs --migrate-only, drops privileges, and whose Deployments roll when the secret changes."
