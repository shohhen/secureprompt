#!/usr/bin/env python3
"""Parse `docker compose config` output on stdin and assert the WS6-5
appliance properties. Called by scripts/ci/check-compose-appliance.sh once per
compose file / overlay combination.

A parser, not a grep: `${VAR:-default}` interpolation, `extends`, and the
onprem OVERLAY all change the effective service definition, and none of them
are visible in the source YAML.
"""
import sys

import yaml

# Services that legitimately have no memory/cpu limit.
#   (none — every container in an appliance VM competes for the same RAM)
EXEMPT_LIMITS: set = set()

# Services that do not talk to Redis or ClickHouse and so need no credential.
NO_DATASTORE_CLIENTS = {
    "postgres", "redis", "clickhouse", "qdrant", "grafana", "prometheus",
    "alertmanager", "librechat-mongo", "librechat", "librechat-nginx",
    "secureprompt-ml", "web", "backup", "db-migrate",
}

# Services whose REDIS_URL must carry a password.
REDIS_CLIENTS = {"api", "worker"}
# Services whose ClickHouse credentials must be present.
CH_CLIENTS = {"api", "worker"}


def env_of(svc: dict) -> dict:
    env = svc.get("environment") or {}
    if isinstance(env, list):
        out = {}
        for item in env:
            if "=" in item:
                k, v = item.split("=", 1)
                out[k] = v
            else:
                out[item] = None
        return out
    return {k: ("" if v is None else str(v)) for k, v in env.items()}


def main() -> int:
    label = sys.argv[1]
    mode = sys.argv[2]
    doc = yaml.safe_load(sys.stdin.read()) or {}
    services = doc.get("services") or {}

    problems = []

    # PREMISE — an empty render satisfies every "every service must ..."
    # assertion for free.
    if not services:
        problems.append("no services rendered at all — nothing was asserted")
    if "api" not in services:
        problems.append("the api service did not render — this check would pass vacuously")

    for name, svc in services.items():
        limits = ((svc.get("deploy") or {}).get("resources") or {}).get("limits") or {}
        if name not in EXEMPT_LIMITS:
            if not limits.get("memory"):
                problems.append(f"{name}: no deploy.resources.limits.memory")
            if not limits.get("cpus"):
                problems.append(f"{name}: no deploy.resources.limits.cpus")

        env = env_of(svc)

        if name in REDIS_CLIENTS and "REDIS_URL" in env:
            url = env["REDIS_URL"] or ""
            # redis://[user]:password@host — an authenticated URL always has an
            # '@'. redis://redis:6379 does not.
            if "@" not in url:
                problems.append(f"{name}: REDIS_URL carries no credential ({url!r})")
            elif not url.startswith("redis://default:"):
                # MEASURED against valkey 8.1.6: the userinfo-with-empty-username
                # form `redis://:pw@host` makes valkey-cli send two-arg AUTH and
                # fail with WRONGPASS. The Rust client happens to be fine with it
                # (redis 1.2.0 maps an empty username to None), but a URL that
                # only works for one of its two consumers is a debugging trap.
                problems.append(
                    f"{name}: REDIS_URL should name the `default` user explicitly "
                    f"({url.split('@')[-1]}) — the empty-username form fails under redis-cli/valkey-cli"
                )

        if name in CH_CLIENTS and "CLICKHOUSE_URL" in env:
            if not env.get("CLICKHOUSE_PASSWORD"):
                problems.append(f"{name}: CLICKHOUSE_URL is set but CLICKHOUSE_PASSWORD is not")
            if not env.get("CLICKHOUSE_USER"):
                problems.append(f"{name}: CLICKHOUSE_URL is set but CLICKHOUSE_USER is not")

    # --- Redis server-side auth ------------------------------------------
    redis = services.get("redis")
    if redis is not None:
        cmd = redis.get("command")
        cmd_s = " ".join(cmd) if isinstance(cmd, list) else (cmd or "")
        if "--requirepass" not in cmd_s:
            problems.append("redis: server does not require a password (--requirepass absent)")
        hc = (redis.get("healthcheck") or {}).get("test")
        hc_s = " ".join(hc) if isinstance(hc, list) else (hc or "")
        # MEASURED: under --requirepass, `redis-cli ping` prints
        # "NOAUTH Authentication required." and exits 0. A healthcheck that
        # only runs `redis-cli ping` therefore reports healthy no matter what.
        if hc_s and "PONG" not in hc_s:
            problems.append(
                "redis: healthcheck does not check for PONG — measured, `redis-cli ping` "
                "exits 0 while printing NOAUTH, so the check would be vacuous"
            )

    # --- ClickHouse server-side auth --------------------------------------
    ch = services.get("clickhouse")
    if ch is not None:
        env = env_of(ch)
        if not env.get("CLICKHOUSE_PASSWORD"):
            problems.append("clickhouse: CLICKHOUSE_PASSWORD is unset — the default user has no password")

    # --- air-gap: nothing may be left on `build:` -------------------------
    if mode == "airgap":
        for name, svc in services.items():
            if not svc.get("image"):
                problems.append(f"{name}: no image: — an air-gapped host has nothing to build from")
            if svc.get("pull_policy") != "never":
                problems.append(
                    f"{name}: pull_policy={svc.get('pull_policy')!r}, not 'never' — on an "
                    "air-gapped host that is a registry call that hangs and fails, after "
                    "`docker load` has already put the exact image in the local store"
                )

    if problems:
        print(f"ERROR: [{label}] compose appliance:", file=sys.stderr)
        for p in problems:
            print(f"       {p}", file=sys.stderr)
        return 1

    print(f"  ok  [{label}] — {len(services)} services, limits + datastore auth + pinning hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
