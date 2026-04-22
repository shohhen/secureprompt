//! Assert the public-signup path + schemas are present in the OpenAPI
//! document. Parses the JSON at runtime (the `include_str!` in
//! `http/mod.rs::openapi_json` already guarantees compile-time parse validity,
//! but this test asserts the structural expectation that downstream tools
//! (Postman import, type generators) rely on).

use serde_json::Value;

const SPEC: &str =
    include_str!("../../secureprompt-schemas/openapi/v1/openapi.json");

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
