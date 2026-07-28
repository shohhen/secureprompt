pub mod client;
pub mod types;

pub use client::MlSidecarClient;
pub use types::{
    InjectionRequest, InjectionResponse, MlDetection, MlDetectionOutcome, NerRequest, NerResponse,
    RagCheckResponse, SidecarCoverage, SidecarOutage,
};
