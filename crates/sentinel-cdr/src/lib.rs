#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod engine;
pub mod error;
pub mod policy;
pub mod sanitizers;
pub mod service;
pub mod worker;

pub use engine::{CdrEngine, DetectedFormat, InspectionAssessment, SanitizationReport};
pub use error::{CdrError, Result};
pub use policy::{
    ResourceBudget, SanitizationPolicy, SignedPdfPolicy, DEFAULT_JPEG_REENCODE_QUALITY,
};
pub use service::CdrGrpcService;
pub use worker::{WorkerLauncher, WorkerRequest, WorkerResponse};
