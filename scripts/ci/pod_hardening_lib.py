#!/usr/bin/env python3
"""Parse a rendered Helm manifest on stdin and assert the WS6-5 pod-hardening
properties. Called by scripts/ci/check-pod-hardening.sh once per render mode.

This is a PARSER, deliberately, not a grep. The single most expensive defect
found on this chart (MR1 C4) was a `grep` that found an env var inside an
`{{- if }}` whose default was false; the reviewer recorded the wiring as sound
and withdrew it only after rendering. Same lesson, same shape of check.
"""
import sys

import yaml

# ---------------------------------------------------------------------------
# readOnlyRootFilesystem exemptions.
#
# Every entry was MEASURED by starting the exact pinned image under
# `docker run --read-only` on 2026-08-05 and reading the failure, not inferred
# from documentation. The workloads NOT listed here were measured to start
# clean read-only and so carry the setting.
# ---------------------------------------------------------------------------
EXEMPT_RO_ROOTFS = {
    # secureprompt-ml.  NOT MEASURED. The image is 12.6 GB and is deliberately
    # excluded from the CI `build` stage (.gitlab-ci.yml "KNOWN CAVEATS": it
    # needs the raw model DEK), so it is not built here and was never started
    # read-only. Asserting a property nobody executed is the failure mode this
    # repo has been burned by, so the chart ships
    # ml.security.readOnlyRootFilesystem=false and an operator who has the
    # image can flip it -- /tmp already has an emptyDir, so that is a values
    # change with no template change.
    "ml": "12.6 GB image is excluded from CI build (needs the model DEK); never started read-only, so not asserted",
    # librechat + mongo.  NOT MEASURED -- images not built in this environment.
    "librechat": "image not built in this environment; never started read-only, so not asserted",
    "mongo": "image not built in this environment; never started read-only, so not asserted",
    # backup CronJob. NOT MEASURED -- sp-backup is built out-of-band.
    "backup": "sp-backup image is built out-of-band; never started read-only, so not asserted",
}

# ---------------------------------------------------------------------------
# runAsNonRoot exemptions. Same rule: measured, not assumed.
#
# postgres is NOT here, and the reason is worth recording. It was first
# recorded as impossible -- `docker run --user 999:999` gave
#   initdb: error: could not change permissions of directory
#   "/var/lib/postgresql/data": Operation not permitted
# -- and the conclusion was wrong, because 999 is the postgres uid on the
# DEBIAN image. `id postgres` inside postgres:16-alpine is 70. At uid 70 the
# same run reaches "database system is ready to accept connections", including
# against the 0775 root:70 data dir a k8s fsGroup leaves behind. The chart also
# already set PGDATA to a subdirectory of the mount, which is the other half of
# the usual problem.
# ---------------------------------------------------------------------------
EXEMPT_NONROOT = {
    "librechat": "image not built in this environment; not asserted",
    "mongo": "image not built in this environment; not asserted",
    "backup": "sp-backup image is built out-of-band; not asserted",
}

WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob")


def pod_spec(doc):
    if doc["kind"] == "CronJob":
        return doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    return doc["spec"]["template"]["spec"]


def main() -> int:
    label = sys.argv[1] if len(sys.argv) > 1 else "?"
    docs = [d for d in yaml.safe_load_all(sys.stdin.read()) if d]

    problems = []
    seen_container_keys = set()
    workloads = 0
    netpols = []

    for doc in docs:
        kind = doc.get("kind")
        if kind == "NetworkPolicy":
            netpols.append(doc)
        if kind not in WORKLOAD_KINDS:
            continue
        workloads += 1
        name = doc["metadata"]["name"]
        spec = pod_spec(doc)
        for group in ("initContainers", "containers"):
            for c in spec.get(group) or []:
                cname = c["name"]
                seen_container_keys.add(cname)
                where = f"{kind}/{name}:{cname}"

                res = c.get("resources") or {}
                for side in ("requests", "limits"):
                    block = res.get(side) or {}
                    for field in ("cpu", "memory"):
                        if not block.get(field):
                            problems.append(f"{where}: resources.{side}.{field} is unset")

                sc = c.get("securityContext") or {}
                if sc.get("allowPrivilegeEscalation") is not False:
                    problems.append(f"{where}: allowPrivilegeEscalation is not false")
                drop = ((sc.get("capabilities") or {}).get("drop")) or []
                if "ALL" not in drop:
                    problems.append(f"{where}: capabilities.drop does not include ALL")

                if cname not in EXEMPT_NONROOT and sc.get("runAsNonRoot") is not True:
                    problems.append(f"{where}: runAsNonRoot is not true")
                if cname not in EXEMPT_RO_ROOTFS and sc.get("readOnlyRootFilesystem") is not True:
                    problems.append(f"{where}: readOnlyRootFilesystem is not true")

    # PREMISE. An empty or api-less manifest satisfies every assertion above
    # for free.
    if workloads == 0:
        problems.append("no workloads rendered at all — nothing was asserted")
    if "api" not in seen_container_keys:
        problems.append("the api container did not render — this check would pass vacuously")

    # NetworkPolicy. A policy that selects nothing, or one with an empty-set
    # ingress that allows all, is not a policy.
    if not netpols:
        problems.append("no NetworkPolicy rendered")
    else:
        default_deny = [
            p for p in netpols
            if (p["spec"].get("podSelector") == {} or p["spec"].get("podSelector") is None)
            and "Ingress" in (p["spec"].get("policyTypes") or [])
            and not (p["spec"].get("ingress") or [])
        ]
        if not default_deny:
            problems.append(
                "no default-deny NetworkPolicy (empty podSelector, policyTypes[Ingress], no ingress rules)"
            )

    # The exemption list may not rot. An exemption for a container name that
    # this chart no longer renders in ANY mode would be a permanent hole.
    # Checked only in the mode that renders the most, to avoid false alarms on
    # modes that legitimately omit a workload.
    if label == "librechat enabled":
        for cname in EXEMPT_RO_ROOTFS:
            if cname not in seen_container_keys and cname != "backup":
                problems.append(
                    f"exemption for '{cname}' names a container that no longer renders — drop it"
                )

    if problems:
        print(f"ERROR: [{label}] pod hardening:", file=sys.stderr)
        for p in problems:
            print(f"       {p}", file=sys.stderr)
        return 1

    print(f"  ok  [{label}] — {workloads} workloads, "
          f"{len(seen_container_keys)} distinct containers, {len(netpols)} NetworkPolicies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
