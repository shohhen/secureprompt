//! WS6-4 — read the served route table **out of the router**, at runtime.
//!
//! # Why this exists
//!
//! `secureprompt-schemas/openapi/v1/openapi.{yaml,json}` is hand-authored and
//! the dashboard's TypeScript client is generated from it. Before this module
//! the only thing keeping the two in agreement was somebody remembering: the
//! spec sat at 35 paths while [`crate::http::build_router`] served 51, and the
//! entire admin surface (`/v1/users`, `/v1/license`, `/v1/data-inventory`,
//! `/v1/leak-report`, `/v1/audit-exports`, the session endpoints) was absent.
//! Measured on `main` @ `fb5e1df`, 2026-08-05.
//!
//! A hand-maintained list of "routes we serve" would drift the same way, so
//! this follows the pattern the repository already uses for its strongest
//! guards — `rls_call_site_guard` reads armed tables from `pg_class`,
//! `tenancy_predicate_guard` reads tenant tables from `information_schema`,
//! `admin_audit`'s vocabulary test reads from `pg_get_constraintdef`. The
//! source of truth is queried, never transcribed.
//!
//! # How
//!
//! `axum::Router` exposes no route-listing API, but its `Debug` impl prints
//! `path_router: PathRouter { routes: {RouteId(n): MethodRouter(..)}, node:
//! Node { paths: {RouteId(n): "/path"} } }`, and `MethodRouter`'s `Debug`
//! prints the `Allow` header axum itself would send on a 405. Both are
//! *derived from the live router value*, including everything `.nest()`
//! flattened and everything `.layer()` wrapped, so a route added anywhere in
//! `build_router`'s tree shows up here with no edit to this file.
//!
//! That makes the `Debug` format load-bearing, which is a real cost. It is
//! paid down two ways, both of which fail LOUDLY rather than returning an
//! empty table:
//!
//! * [`parse_route_table`] is unit-tested against a synthetic router built in
//!   this file, so an axum upgrade that changes the format fails here — in a
//!   test whose expected value is written out longhand — instead of silently
//!   reporting "the router serves nothing".
//! * [`route_table`] itself asserts the table is non-empty and contains a
//!   route that cannot disappear without a deliberate product change.
//!
//! Verified against axum 0.8.9 (`Cargo.lock`).

use axum::Router;
use std::collections::{BTreeMap, BTreeSet};

/// Path → set of HTTP methods, as the router will actually dispatch them.
pub type RouteTable = BTreeMap<String, BTreeSet<String>>;

/// A route every deployment serves. Used as this module's own premise
/// assertion: if the `Debug` format changes under an axum upgrade the parser
/// returns nothing, and "nothing" must not read as "no routes are missing
/// from the spec".
const ANCHOR_ROUTE: &str = "/v1/chat/completions";

/// The live route table of `router`.
///
/// # Panics
/// Panics if the table comes back empty or without [`ANCHOR_ROUTE`] — that is
/// a broken parser, not a router with no routes, and a guard built on a broken
/// parser passes vacuously.
#[must_use]
pub fn route_table(router: &Router) -> RouteTable {
    let table = parse_route_table(&format!("{router:?}"));
    assert!(
        !table.is_empty(),
        "route_table() extracted 0 routes from a live axum Router. The Debug \
         format this module parses has changed (axum upgrade?) — fix \
         parse_route_table rather than letting an empty table read as 'the \
         spec is complete'."
    );
    assert!(
        table.contains_key(ANCHOR_ROUTE),
        "route_table() extracted {} routes but not the anchor {ANCHOR_ROUTE}. \
         Either the parser is partially broken or the gateway stopped serving \
         its primary endpoint; both need a human.",
        table.len()
    );
    table
}

/// Pure parser over `format!("{router:?}")`. Split out from [`route_table`] so
/// it can be tested against a string whose expected output is written by hand.
#[must_use]
pub fn parse_route_table(debug: &str) -> RouteTable {
    // Only `path_router` — `fallback_router` holds axum's internal `/` and
    // `/{*__private__axum_fallback}` entries, which are not served routes.
    let Some(path_router) = balanced_body(debug, "path_router: PathRouter {", '{', '}') else {
        return RouteTable::new();
    };

    // `routes: {RouteId(n): MethodRouter(MethodRouter { .. allow_header: .. })}`
    let methods_by_id: BTreeMap<u64, BTreeSet<String>> =
        match balanced_body(path_router, "routes: {", '{', '}') {
            Some(routes) => split_route_id_entries(routes)
                .into_iter()
                .map(|(id, value)| (id, methods_from_endpoint(value)))
                .collect(),
            None => BTreeMap::new(),
        };

    // `node: Node { paths: {RouteId(n): "/path"} }`
    let Some(node) = balanced_body(path_router, "node: Node {", '{', '}') else {
        return RouteTable::new();
    };
    let Some(paths) = balanced_body(node, "paths: {", '{', '}') else {
        return RouteTable::new();
    };

    let mut table = RouteTable::new();
    for (id, value) in split_route_id_entries(paths) {
        let Some(path) = value
            .trim()
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
        else {
            continue;
        };
        table
            .entry(path.to_owned())
            .or_default()
            .extend(methods_by_id.get(&id).cloned().unwrap_or_default());
    }
    table
}

/// The body between `open`/`close` immediately following `marker`.
fn balanced_body<'a>(haystack: &'a str, marker: &str, open: char, close: char) -> Option<&'a str> {
    let start = haystack.find(marker)? + marker.len();
    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, ch) in haystack[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            c if c == open => depth += 1,
            c if c == close => {
                depth -= 1;
                if depth == 0 {
                    return Some(&haystack[start..start + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Split a `{RouteId(n): value, RouteId(m): value}` body into `(n, value)`.
///
/// Safe to do by splitting on the literal `RouteId(` because `RouteId` appears
/// only as a map key: the values are `MethodRouter(..)`, `Route(..)` and
/// path string literals, none of which contain the token.
fn split_route_id_entries(body: &str) -> Vec<(u64, &str)> {
    let mut out = Vec::new();
    for chunk in body.split("RouteId(").skip(1) {
        let Some((id_raw, rest)) = chunk.split_once(')') else {
            continue;
        };
        let Ok(id) = id_raw.trim().trim_end_matches(',').parse::<u64>() else {
            continue;
        };
        let value = rest.trim_start().strip_prefix(':').unwrap_or(rest).trim();
        // Drop the separator that belongs to the *next* entry.
        out.push((id, value.trim_end().trim_end_matches(',').trim_end()));
    }
    out
}

/// Methods from `MethodRouter(MethodRouter { .. allow_header: Bytes(b"GET,POST") })`.
///
/// axum builds that byte string from the method handlers actually registered
/// (`append_allow_header`) and sends it as the `Allow` header on its own 405,
/// so it is the router's own answer to "what verbs does this path take", not
/// a re-derivation of it.
fn methods_from_endpoint(value: &str) -> BTreeSet<String> {
    let Some(rest) = value.split("allow_header: ").nth(1) else {
        return BTreeSet::new();
    };
    let Some(bytes) = rest.strip_prefix("Bytes(b\"") else {
        // `None` (no verbs) or `Skip` (`any()` / `any_service()`, which accepts
        // every verb and therefore pins none).
        return BTreeSet::new();
    };
    let Some((list, _)) = bytes.split_once('"') else {
        return BTreeSet::new();
    };
    list.split(',')
        .map(str::trim)
        .filter(|m| !m.is_empty())
        // axum adds HEAD implicitly wherever GET is registered; it is not a
        // documented operation in OpenAPI and every spec would have to carry a
        // redundant `head:` entry alongside every `get:`.
        .filter(|m| *m != "HEAD")
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{delete, get, patch, post, put};

    /// The positive control for the whole module: a router whose contents are
    /// written out longhand here, so a parser that returns the wrong thing
    /// cannot look correct.
    fn synthetic_router() -> Router {
        Router::<()>::new()
            .route("/alpha", get(|| async {}).post(|| async {}))
            .route("/alpha/{id}", delete(|| async {}))
            .nest(
                "/nested",
                Router::<()>::new()
                    .route("/beta", put(|| async {}))
                    .route("/beta/{a}/gamma/{b}", patch(|| async {})),
            )
            // The production router puts the whole tree under middleware; make
            // sure a wrapped endpoint still reports its verbs.
            .layer(axum::middleware::from_fn(
                |req: axum::extract::Request, next: axum::middleware::Next| async move {
                    next.run(req).await
                },
            ))
    }

    #[test]
    fn extracts_paths_and_methods_from_a_router_whose_contents_are_known() {
        let table = parse_route_table(&format!("{:?}", synthetic_router()));

        let expected: RouteTable = [
            ("/alpha", vec!["GET", "POST"]),
            ("/alpha/{id}", vec!["DELETE"]),
            ("/nested/beta", vec!["PUT"]),
            ("/nested/beta/{a}/gamma/{b}", vec!["PATCH"]),
        ]
        .into_iter()
        .map(|(p, m)| {
            (
                p.to_owned(),
                m.into_iter().map(str::to_owned).collect::<BTreeSet<_>>(),
            )
        })
        .collect();

        assert_eq!(table, expected);
    }

    /// Deletion check: remove a route and the extraction must *differ*. Without
    /// this, `extracts_paths_and_methods...` would still pass if the parser
    /// returned a hard-coded constant.
    #[test]
    fn removing_a_route_changes_the_extracted_table() {
        let full = parse_route_table(&format!("{:?}", synthetic_router()));
        let smaller = parse_route_table(&format!(
            "{:?}",
            Router::<()>::new()
                .route("/alpha", get(|| async {}).post(|| async {}))
                .route("/alpha/{id}", delete(|| async {}))
        ));
        assert_ne!(full, smaller);
        assert!(full.contains_key("/nested/beta"));
        assert!(!smaller.contains_key("/nested/beta"));
    }

    /// Adding a verb to an existing path must change that path's method set —
    /// the path-level check above cannot see this.
    #[test]
    fn adding_a_verb_changes_only_that_paths_method_set() {
        let one = parse_route_table(&format!(
            "{:?}",
            Router::<()>::new().route("/x", get(|| async {}))
        ));
        let two = parse_route_table(&format!(
            "{:?}",
            Router::<()>::new().route("/x", get(|| async {}).post(|| async {}))
        ));
        assert_eq!(one["/x"], BTreeSet::from(["GET".to_owned()]));
        assert_eq!(
            two["/x"],
            BTreeSet::from(["GET".to_owned(), "POST".to_owned()])
        );
        assert_ne!(one, two);
    }

    /// axum's internal fallback entries live in `fallback_router` and must not
    /// leak into the table — `/{*__private__axum_fallback}` is not an endpoint
    /// anybody can document.
    #[test]
    fn fallback_router_entries_are_excluded() {
        let table = parse_route_table(&format!(
            "{:?}",
            Router::<()>::new()
                .route("/real", get(|| async {}))
                .fallback(|| async { "nope" })
        ));
        assert_eq!(table.keys().collect::<Vec<_>>(), vec!["/real"]);
    }

    /// A broken parse must be visibly empty rather than partially right.
    #[test]
    fn unparseable_debug_yields_an_empty_table() {
        assert!(parse_route_table("Router { something_else: 1 }").is_empty());
    }

    /// HEAD is axum's implicit companion to GET, not a documented operation.
    #[test]
    fn head_is_dropped_but_get_is_kept() {
        let methods = methods_from_endpoint("MethodRouter { allow_header: Bytes(b\"GET,HEAD\") }");
        assert_eq!(methods, BTreeSet::from(["GET".to_owned()]));
        assert!(!methods.contains("HEAD"));
    }

    #[test]
    fn route_table_accepts_a_real_router() {
        // `route_table` (unlike `parse_route_table`) asserts its own premise;
        // exercise that path on a router that legitimately has the anchor.
        let table = route_table(&Router::<()>::new().route(ANCHOR_ROUTE, post(|| async {})));
        assert_eq!(table[ANCHOR_ROUTE], BTreeSet::from(["POST".to_owned()]));
    }

    #[test]
    #[should_panic(expected = "extracted 0 routes")]
    fn route_table_panics_rather_than_returning_an_empty_table() {
        // An empty router is indistinguishable from a broken parser, and the
        // whole point of the guard is that "I found nothing" must never be
        // read as "nothing is missing".
        let _ = route_table(&Router::<()>::new());
    }
}
