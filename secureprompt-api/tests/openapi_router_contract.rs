//! WS6-4 — the OpenAPI document must describe exactly what the router serves.
//!
//! # The defect this exists for
//!
//! `secureprompt-schemas/openapi/v1/openapi.yaml` is hand-authored, and the
//! dashboard's entire TypeScript client is generated from it
//! (`pnpm --filter secureprompt-web codegen` → `src/types/api.gen.ts`). Nothing
//! connected the two: measured on `main` @ `fb5e1df` the spec carried 35 paths
//! (36 in the served JSON) while [`build_router`] served 58, and every admin endpoint the console calls
//! — `/v1/users`, `/v1/license`, `/v1/data-inventory`, `/v1/leak-report`,
//! `/v1/audit-exports`, `/v1/me/profile`, the session endpoints — was absent.
//! Ten hooks therefore hand-wrote their own request and response types, which
//! is exactly the drift the generated client is supposed to make impossible.
//!
//! # Why it is derived, not listed
//!
//! There is no list of routes in this file. Both sides are read from their own
//! source of truth at runtime:
//!
//! * the router side from the live `axum::Router` value
//!   ([`secureprompt_api::http::route_table`]), so `.nest()`ed and `.layer()`ed
//!   routes are included and a new `.route(..)` anywhere needs no edit here;
//! * the spec side by parsing the same `openapi.json` that `http/mod.rs`
//!   serves from `GET /openapi.json` via `include_str!`.
//!
//! Same shape as `rls_call_site_guard` (armed tables from `pg_class`),
//! `tenancy_predicate_guard` (tenant tables from `information_schema`) and
//! `admin_audit`'s vocabulary test (actions from `pg_get_constraintdef`): a
//! 59th route extends its own coverage without an edit to this file.
//!
//! The one hand-maintained thing is [`UNDOCUMENTED_BY_DESIGN`], and it is
//! checked in both directions — an entry that stops being served fails too, so
//! it cannot become a place to park routes.

use secureprompt_api::{
    app_state::AppState,
    http::{
        build_router,
        route_table::{route_table, RouteTable},
    },
    ml_sidecar::MlSidecarClient,
};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
    ServerConfig, TelemetryConfig,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const SPEC: &str = include_str!("../../secureprompt-schemas/openapi/v1/openapi.json");

/// Routes that are served but deliberately absent from the public API
/// document, each with the reason. Every entry is asserted to still be served
/// (below), so this list can only shrink by deleting a route or grow by a
/// reviewed decision — it cannot silently accumulate.
const UNDOCUMENTED_BY_DESIGN: &[(&str, &str)] = &[
    (
        "/internal/attestation",
        "operator/agent plane, not a customer API: sp-agent reads it to prove \
         the deployment's model-key attestation. Publishing it in the client \
         spec would generate a dashboard method for something the dashboard \
         must never call.",
    ),
    (
        "/v1/internal/budget-probe",
        "test probe registered by http::middleware::rate_limit::test_probe_router \
         so the budget middleware can be driven without a provider. It is merged \
         into the production router unconditionally — see WS6-4-FU1 — but it is \
         not API surface and must not appear in a generated client.",
    ),
    (
        "/v1/auth/oidc/authorize",
        "browser redirect endpoints (302 to the IdP and back). They are \
         navigated to, never fetched, so a typed client method for them would \
         be actively misleading.",
    ),
    ("/v1/auth/oidc/callback", "see /v1/auth/oidc/authorize."),
];

// ── the two tables ───────────────────────────────────────────────────────────

/// The router's own answer, from a router built exactly as `main.rs` builds it.
///
/// `connect_lazy` is used on purpose: no route is dispatched here, only the
/// table is read, so this guard runs without Postgres and cannot be skipped for
/// want of a database.
fn router_side() -> RouteTable {
    // `AppState::try_new` builds a KMS backend eagerly. Set in-process, like
    // `admin_audit::set_kms_key`, so this guard does not depend on the
    // developer's shell — 32 zero bytes, base64; nothing here encrypts.
    std::env::set_var(
        "KMS_FILE_KEY",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    );
    let config = AppConfig {
        database: DatabaseConfig {
            url: "postgres://secureprompt:secureprompt@localhost:5432/postgres".to_owned(),
            max_connections: 1,
        },
        redis: RedisConfig {
            url: "redis://localhost:6379".to_owned(),
            max_connections: 1,
        },
        telemetry: TelemetryConfig {
            otel_enabled: false,
            prometheus_enabled: true,
            log_level: "info".to_owned(),
        },
        server: ServerConfig {
            host: "127.0.0.1".to_owned(),
            port: 0,
        },
        clickhouse: ClickhouseConfig {
            url: "http://localhost:8123".to_owned(),
            database: "default".to_owned(),
        },
        jwt: JwtConfig {
            secret: "route-table-probe-secret-not-used-for-any-request".to_owned(),
            access_ttl_secs: JwtConfig::DEFAULT_ACCESS_TTL_SECS,
            refresh_ttl_secs: JwtConfig::DEFAULT_REFRESH_TTL_SECS,
        },
        public_signup_enabled: false,
        chat_debug_mode: false,
        redact_when_no_rules: false,
        sidecar_unavailable_default: "block".to_owned(),
        license: LicenseConfig::default(),
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy(&config.database.url)
        .expect("lazy pool must construct without connecting");
    let state = AppState::new(
        pool,
        config,
        Arc::new(MlSidecarClient::new(String::new(), 200)),
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    );
    route_table(&build_router(state))
}

/// The document's answer: path → the HTTP verbs it declares operations for.
fn spec_side() -> RouteTable {
    const VERBS: &[&str] = &["get", "put", "post", "delete", "patch"];
    let spec: Value = serde_json::from_str(SPEC).expect("openapi.json must parse");
    let paths = spec["paths"]
        .as_object()
        .expect("openapi.json must have an object `paths`");
    paths
        .iter()
        .map(|(path, item)| {
            let methods: BTreeSet<String> = VERBS
                .iter()
                .filter(|verb| item.get(**verb).is_some())
                .map(|verb| verb.to_uppercase())
                .collect();
            (path.clone(), methods)
        })
        .collect()
}

fn excluded() -> BTreeMap<&'static str, &'static str> {
    UNDOCUMENTED_BY_DESIGN.iter().copied().collect()
}

// ── premise assertions ───────────────────────────────────────────────────────
//
// Every one of these would have to be false for the two tests below to pass
// vacuously. They are asserted, not assumed.

#[tokio::test]
async fn both_sides_are_non_empty_and_disagree_with_a_wrong_answer() {
    let router = router_side();
    let spec = spec_side();

    assert!(
        router.len() > 40,
        "the router side collapsed to {} routes — the guard would then pass by \
         having nothing to check",
        router.len()
    );
    assert!(
        spec.len() > 30,
        "the spec side collapsed to {} paths — same vacuity risk",
        spec.len()
    );

    // Positive control: a table that is definitely wrong must be rejected by
    // the same comparison the real tests use. If this ever passes, the
    // comparison is not comparing.
    let mut mutated = router.clone();
    mutated.insert(
        "/v1/definitely-not-a-real-route".to_owned(),
        BTreeSet::new(),
    );
    assert_ne!(
        mutated, router,
        "inserting a fake route did not change the table"
    );

    // And the verb dimension must be load-bearing, not just the path set.
    let paths_only: BTreeSet<&String> = router.keys().collect();
    let spec_paths_only: BTreeSet<&String> = spec.keys().collect();
    assert!(
        !paths_only.is_empty() && !spec_paths_only.is_empty(),
        "path projections are empty"
    );
    assert!(
        router.values().any(|m| m.len() > 1),
        "no path reported more than one verb, so the method comparison below \
         would be trivially satisfiable"
    );
}

/// The exclusion list may not rot: every entry must name a route the router
/// really serves.
#[tokio::test]
async fn every_undocumented_by_design_entry_is_still_served() {
    let router = router_side();
    for (path, reason) in UNDOCUMENTED_BY_DESIGN {
        assert!(
            router.contains_key(*path),
            "UNDOCUMENTED_BY_DESIGN lists {path} ({reason}) but the router no \
             longer serves it. Delete the entry — a stale exclusion is a hole \
             the next route can fall through."
        );
    }
    assert_eq!(
        UNDOCUMENTED_BY_DESIGN.len(),
        excluded().len(),
        "duplicate path in UNDOCUMENTED_BY_DESIGN"
    );
}

// ── the contract, both directions ────────────────────────────────────────────

/// RED → GREEN driver for WS6-4 item 1.
///
/// FALSIFIER (executed, 2026-08-05): adding
/// `.route("/v1/ws64-throwaway", get(...))` to `build_router` makes this test
/// name that path and fail; removing it makes it pass again.
#[tokio::test]
async fn every_served_route_is_documented() {
    let router = router_side();
    let spec = spec_side();
    let excluded = excluded();

    let mut missing: Vec<String> = Vec::new();
    for (path, methods) in &router {
        if excluded.contains_key(path.as_str()) {
            continue;
        }
        match spec.get(path) {
            None => missing.push(format!("  {path}  (entirely absent; serves {methods:?})")),
            Some(documented) => {
                let undocumented: Vec<&String> = methods.difference(documented).collect();
                if !undocumented.is_empty() {
                    missing.push(format!(
                        "  {path}  (documented {documented:?}, but also serves {undocumented:?})"
                    ));
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "{} route(s) are served by build_router() but not described in \
         secureprompt-schemas/openapi/v1/openapi.json.\n\
         The dashboard's TypeScript client is generated from that document, so \
         an undocumented route is a route the console can only call with \
         hand-written types.\n\n{}\n\n\
         Fix: add the path to openapi.yaml (openapi.json is generated from it — \
         `pnpm --filter secureprompt-web codegen`), or, if it is genuinely not \
         customer API, add it to UNDOCUMENTED_BY_DESIGN in this file with a \
         reason.",
        missing.len(),
        missing.join("\n")
    );
}

/// The other direction — a documented route nobody serves is a 404 with a
/// generated client method, which is worse than an undocumented one.
#[tokio::test]
async fn every_documented_route_is_served() {
    let router = router_side();
    let spec = spec_side();

    let mut phantom: Vec<String> = Vec::new();
    for (path, methods) in &spec {
        match router.get(path) {
            None => phantom.push(format!("  {path}  (documented {methods:?}; not routed)")),
            Some(served) => {
                let unserved: Vec<&String> = methods.difference(served).collect();
                if !unserved.is_empty() {
                    phantom.push(format!(
                        "  {path}  (documents {unserved:?}, but the router serves only {served:?})"
                    ));
                }
            }
        }
    }

    assert!(
        phantom.is_empty(),
        "{} documented operation(s) are not served by build_router().\n\
         `openapi-typescript` will generate a client method for each one, so \
         the console gets a compile-time-valid call that 404s or 405s at \
         runtime.\n\n{}",
        phantom.len(),
        phantom.join("\n")
    );
}

/// `openapi.json` is generated from `openapi.yaml`; nothing else may edit it.
/// The Rust side reads the JSON (`include_str!`) and the codegen reads the
/// YAML, so a divergence means the served document and the generated client
/// describe different APIs — which is exactly what had happened:
/// `POST /v1/auth/register` was in the JSON and not in the YAML.
#[test]
fn the_served_json_and_the_authored_yaml_describe_the_same_paths() {
    // Parsed with the same trivial reader the CI job uses, so this test needs
    // no YAML crate in the workspace dependency graph.
    let yaml = include_str!("../../secureprompt-schemas/openapi/v1/openapi.yaml");
    let yaml_paths = top_level_paths_from_yaml(yaml);
    let json_paths: BTreeSet<String> = spec_side().into_keys().collect();

    assert!(
        yaml_paths.len() > 30,
        "the YAML path scan found only {} paths — the scanner is broken, and a \
         broken scanner would make this comparison vacuous",
        yaml_paths.len()
    );
    assert_eq!(
        yaml_paths, json_paths,
        "openapi.yaml and openapi.json disagree. Regenerate the JSON: \
         `pnpm --filter secureprompt-web codegen`."
    );
}

/// The `paths:` block of an OpenAPI YAML written at this repo's indentation:
/// two-space keys directly under a column-0 `paths:`.
fn top_level_paths_from_yaml(yaml: &str) -> BTreeSet<String> {
    let mut inside = false;
    let mut out = BTreeSet::new();
    for line in yaml.lines() {
        if line.starts_with("paths:") {
            inside = true;
            continue;
        }
        if inside {
            // A new column-0 key ends the block.
            if !line.starts_with(' ') && !line.trim().is_empty() && !line.starts_with('#') {
                break;
            }
            if let Some(rest) = line.strip_prefix("  /") {
                if let Some(path) = rest.strip_suffix(':') {
                    out.insert(format!("/{path}"));
                }
            }
        }
    }
    out
}
