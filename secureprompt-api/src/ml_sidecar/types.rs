use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NerRequest {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NerEntity {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub score: f32,
    pub text: String,
    pub compliance_categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NerResponse {
    pub entities: Vec<NerEntity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionRequest {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionResponse {
    pub is_injection: bool,
    pub score: f32,
}

/// Internal type for a single ML-detected entity, mapped to the gateway's Detection type.
#[derive(Debug, Clone)]
pub struct MlDetection {
    pub class: String,
    pub confidence: f32,
    pub span: Option<(usize, usize)>,
    pub value: String,
    pub compliance_categories: Vec<String>,
}
