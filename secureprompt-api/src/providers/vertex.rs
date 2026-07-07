//! Vertex AI provider adapter — Gemini through Google Cloud (Cloud Billing),
//! separate from the AI Studio `google` adapter. See
//! docs/superpowers/specs/2026-07-07-vertex-ai-provider-design.md.

/// Build the Vertex OpenAI-compat chat-completions URL. `global` uses the
/// unprefixed host; every other region uses `{region}-aiplatform...`.
pub(crate) fn vertex_completions_url(region: &str, project: &str) -> String {
    let host = if region == "global" {
        "aiplatform.googleapis.com".to_owned()
    } else {
        format!("{region}-aiplatform.googleapis.com")
    };
    format!(
        "https://{host}/v1/projects/{project}/locations/{region}/endpoints/openapi/chat/completions"
    )
}

/// Vertex OpenAI-compat requires the `google/` publisher prefix; the console
/// stores bare ids. Idempotent.
pub(crate) fn google_prefixed(model: &str) -> String {
    if model.starts_with("google/") {
        model.to_owned()
    } else {
        format!("google/{model}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_regional() {
        assert_eq!(
            vertex_completions_url("us-central1", "proj"),
            "https://us-central1-aiplatform.googleapis.com/v1/projects/proj/locations/us-central1/endpoints/openapi/chat/completions"
        );
    }

    #[test]
    fn url_global() {
        assert_eq!(
            vertex_completions_url("global", "proj"),
            "https://aiplatform.googleapis.com/v1/projects/proj/locations/global/endpoints/openapi/chat/completions"
        );
    }

    #[test]
    fn prefix_added_once() {
        assert_eq!(google_prefixed("gemini-2.5-flash"), "google/gemini-2.5-flash");
        assert_eq!(google_prefixed("google/gemini-2.5-pro"), "google/gemini-2.5-pro");
    }
}
