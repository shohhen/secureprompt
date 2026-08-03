//! Assert the public-signup path + schemas are present in the OpenAPI
//! document. Parses the JSON at runtime (the `include_str!` in
//! `http/mod.rs::openapi_json` already guarantees compile-time parse validity,
//! but this test asserts the structural expectation that downstream tools
//! (Postman import, type generators) rely on).

use serde_json::Value;

const SPEC: &str = include_str!("../../secureprompt-schemas/openapi/v1/openapi.json");

#[test]
fn openapi_contains_register_path() {
    let spec: Value = serde_json::from_str(SPEC).expect("openapi.json must parse");
    let post_register = spec
        .pointer("/paths/~1v1~1auth~1register/post")
        .expect("missing POST /v1/auth/register");

    // Security override: no auth required.
    assert_eq!(post_register["security"], Value::Array(vec![]));

    // References the RegisterRequest schema.
    let req_ref = post_register
        .pointer("/requestBody/content/application~1json/schema/$ref")
        .and_then(|v| v.as_str())
        .expect("requestBody must $ref a schema");
    assert_eq!(req_ref, "#/components/schemas/RegisterRequest");

    // 201 response references the existing TokenResponse schema.
    let resp_ref = post_register
        .pointer("/responses/201/content/application~1json/schema/$ref")
        .and_then(|v| v.as_str())
        .expect("201 response must $ref a schema");
    assert_eq!(resp_ref, "#/components/schemas/TokenResponse");
}

#[test]
fn openapi_contains_register_request_schema() {
    let spec: Value = serde_json::from_str(SPEC).expect("openapi.json must parse");
    let schema = spec
        .pointer("/components/schemas/RegisterRequest")
        .expect("missing RegisterRequest schema");
    let required = schema["required"]
        .as_array()
        .expect("RegisterRequest.required must be an array");
    let required_names: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
    assert!(required_names.contains(&"email"));
    assert!(required_names.contains(&"password"));
    assert!(required_names.contains(&"workspace_name"));
}

// ===========================================================================
// MR1 review M6 — the sidecar failure mode must be documented on every route
// that can produce it, not only on /v1/chat/completions.
// ===========================================================================

/// Every route whose handler can answer 503 from the sidecar gate or set
/// `x-secureprompt-sidecar-degraded`, with the production call site that puts
/// it on this list.
///
/// HAND-WRITTEN ON PURPOSE. Deriving this from the spec would make the test
/// self-satisfying — it would assert that whatever is documented is
/// documented. Deriving it from the router would need the handler bodies, not
/// the route table, because the gate is called INSIDE the handler. So the list
/// is maintained here and the pointer back to the source line is the thing a
/// reviewer checks.
const SIDECAR_GATED_ROUTES: &[(&str, &str)] = &[
    // `with_sidecar_degraded` — routes/openai.rs:169,191,218
    (
        "/v1/chat/completions",
        "routes/openai.rs — with_sidecar_degraded",
    ),
    // routes/openai.rs:304,328
    (
        "/v1/completions",
        "routes/openai.rs — with_sidecar_degraded",
    ),
    // routes/openai.rs:414
    ("/v1/embeddings", "routes/openai.rs — with_sidecar_degraded"),
    // `sidecar_coverage::enforce` + `with_sidecar_degraded`
    (
        "/v1/redact",
        "routes/mcp_routes.rs:114,163 — sidecar_coverage::enforce",
    ),
    (
        "/v1/policy/check",
        "routes/mcp_routes.rs:231,271 — sidecar_coverage::enforce",
    ),
];

/// M6's finding, as an assertion.
///
/// The 503 and the degraded header were added to `/v1/chat/completions` only
/// (`grep -c` on the YAML was 2 and 2), while five endpoints could produce
/// them. The dashboard's TS client is generated from this document by
/// `openapi-typescript`, so an undocumented failure mode is a failure mode the
/// generated client has no type for.
///
/// FALSIFIER: delete the `"503"` entry, or the `headers` block, from any one
/// of the five paths in `openapi.json` and this names that path.
#[test]
fn every_sidecar_gated_route_documents_the_503_and_the_degraded_header() {
    let spec: Value = serde_json::from_str(SPEC).expect("openapi.json must parse");

    for (path, source) in SIDECAR_GATED_ROUTES {
        let pointer = format!("/paths/{}/post/responses", path.replace('/', "~1"));
        let responses = spec
            .pointer(&pointer)
            .unwrap_or_else(|| panic!("{path} is absent from the OpenAPI document ({source})"));

        let five_o_three = responses.get("503").unwrap_or_else(|| {
            panic!(
                "{path} can answer 503 from the sidecar gate ({source}) but the OpenAPI \
                 document does not say so. A client generated from this file has no type \
                 for the failure mode a `block` workspace hits on every request during an \
                 ML-sidecar outage."
            )
        });
        assert_eq!(
            five_o_three.get("$ref").and_then(Value::as_str),
            Some("#/components/responses/SidecarUnavailable"),
            "{path}: the 503 must be the shared SidecarUnavailable response, not a \
             one-off — a per-path description is how the five drifted apart in the \
             first place"
        );

        let header = responses
            .pointer("/200/headers/x-secureprompt-sidecar-degraded")
            .unwrap_or_else(|| {
                panic!(
                    "{path} sets x-secureprompt-sidecar-degraded on success ({source}) but \
                 the OpenAPI document does not declare it, so a generated client cannot \
                 distinguish a floor-only answer from a fully scanned one"
                )
            });
        assert_eq!(
            header.get("$ref").and_then(Value::as_str),
            Some("#/components/headers/SidecarDegraded"),
            "{path}: the header must $ref the shared component so its enum cannot \
             drift between paths"
        );
    }
}

/// The shared header component must enumerate exactly the reason values
/// `CoverageLoss::as_str` can produce (MR1 review M1 established that
/// `partial_coverage` is one of them).
#[test]
fn the_degraded_header_enum_matches_the_coverage_loss_vocabulary() {
    let spec: Value = serde_json::from_str(SPEC).expect("openapi.json must parse");
    let values: Vec<&str> = spec
        .pointer("/components/headers/SidecarDegraded/schema/enum")
        .and_then(Value::as_array)
        .expect("SidecarDegraded header component must declare an enum")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    assert_eq!(
        values,
        vec![
            "unconfigured",
            "disabled",
            "circuit_open",
            "all_calls_failed",
            "partial_coverage",
        ],
        "the documented reason vocabulary drifted from CoverageLoss::as_str — see \
         `observability::metrics::tests::sidecar_unavailable_reason_label_domain`, \
         which pins the same five on the metric label"
    );
}
