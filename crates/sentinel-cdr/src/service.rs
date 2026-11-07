use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info, warn};

use sentinel_proto::content_disarm_service_server::ContentDisarmService;
use sentinel_proto::{
    disarm_request, disarm_response, DisarmError, DisarmRequest, DisarmResponse, FileFormatType,
    HealthCheckRequest, HealthCheckResponse, InspectRequest, InspectResponse, SanitizationSummary,
    SanitizedElement,
};

use crate::engine::{CdrEngine, DetectedFormat};
use crate::policy::SanitizationPolicy;
use crate::worker::{WorkerLauncher, WorkerRequest};

/// RAII Session Guard (`BUG-CDR-01`)
///
/// Guarantees `active_sessions` is decremented strictly when the spawned streaming task
/// finishes or unwinds, preventing premature decrement on function return.
struct SessionGuard {
    active_sessions: Arc<AtomicU64>,
}

impl SessionGuard {
    fn acquire(active_sessions: Arc<AtomicU64>) -> Self {
        active_sessions.fetch_add(1, Ordering::AcqRel);
        Self { active_sessions }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.active_sessions.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct CdrGrpcService {
    engine: Arc<CdrEngine>,
    active_sessions: Arc<AtomicU64>,
    total_processed: Arc<AtomicU64>,
    cpu_semaphore: Arc<Semaphore>,
}

impl CdrGrpcService {
    pub fn new(policy: SanitizationPolicy) -> Self {
        Self::from_engine(CdrEngine::new(policy))
    }

    pub fn from_engine(engine: CdrEngine) -> Self {
        let parallelism = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            engine: Arc::new(engine),
            active_sessions: Arc::new(AtomicU64::new(0)),
            total_processed: Arc::new(AtomicU64::new(0)),
            cpu_semaphore: Arc::new(Semaphore::new(parallelism)),
        }
    }

    pub fn active_sessions_count(&self) -> u64 {
        self.active_sessions.load(Ordering::Acquire) + WorkerLauncher::active_workers_count()
    }

    pub fn total_processed_count(&self) -> u64 {
        self.total_processed
            .load(Ordering::Acquire)
            .max(WorkerLauncher::processed_ok_count())
    }

    fn map_detected_format(fmt: DetectedFormat) -> i32 {
        match fmt {
            DetectedFormat::Pdf => FileFormatType::FormatPdf as i32,
            DetectedFormat::Docx => FileFormatType::FormatDocx as i32,
            DetectedFormat::Xlsx => FileFormatType::FormatXlsx as i32,
            DetectedFormat::Pptx => FileFormatType::FormatPptx as i32,
            DetectedFormat::Jpeg => FileFormatType::FormatJpeg as i32,
            DetectedFormat::Png => FileFormatType::FormatPng as i32,
            DetectedFormat::WebP => FileFormatType::FormatWebp as i32,
            DetectedFormat::Svg => FileFormatType::FormatSvg as i32,
            DetectedFormat::Ole2 => FileFormatType::FormatOle2 as i32,
            DetectedFormat::PlainText => FileFormatType::FormatTxt as i32,
            DetectedFormat::Csv => FileFormatType::FormatCsv as i32,
            DetectedFormat::ArchiveZip => FileFormatType::FormatArchiveZip as i32,
            DetectedFormat::Unknown => FileFormatType::FormatUnknown as i32,
        }
    }
}

#[tonic::async_trait]
impl ContentDisarmService for CdrGrpcService {
    type StreamDisarmStream =
        Pin<Box<dyn Stream<Item = Result<DisarmResponse, Status>> + Send + 'static>>;

    async fn stream_disarm(
        &self,
        request: Request<Streaming<DisarmRequest>>,
    ) -> Result<Response<Self::StreamDisarmStream>, Status> {
        let mut in_stream = request.into_inner();
        let (out_tx, out_rx) = mpsc::channel(32);

        let engine = Arc::clone(&self.engine);
        let session_guard = SessionGuard::acquire(Arc::clone(&self.active_sessions));
        let total_processed = Arc::clone(&self.total_processed);
        let semaphore = Arc::clone(&self.cpu_semaphore);

        tokio::spawn(async move {
            // Keep RAII guard alive for the entire lifetime of this streaming task (`BUG-CDR-01`)
            let _guard = session_guard;

            let mut effective_policy: SanitizationPolicy = engine.policy().clone();
            let mut max_stream_bytes: usize = effective_policy.max_decompressed_bytes as usize;
            let mut raw_buffer: Vec<u8> = Vec::with_capacity(64 * 1024);
            let mut session_id = uuid::Uuid::new_v4().to_string();
            let mut file_name = String::from("UNKNOWN_FILE");

            // 1. Accumulate incoming chunks with strict pre-CDR byte cap (`BUG-CDR-02`)
            while let Some(chunk_res) = in_stream.next().await {
                match chunk_res {
                    Ok(req) => match req.payload {
                        Some(disarm_request::Payload::Metadata(meta)) => {
                            if !meta.session_id.is_empty() {
                                session_id = meta.session_id;
                            }
                            if !meta.file_name.is_empty() {
                                file_name = meta.file_name;
                            }
                            // Honor caller-supplied DisarmPolicy while enforcing server floor & numeric ceilings (`BUG-CDR-03`, Row 102)
                            effective_policy =
                                SanitizationPolicy::from_proto(meta.policy, engine.policy());
                            max_stream_bytes = effective_policy.max_decompressed_bytes as usize;
                            // Validate DisarmMetadata.total_size_bytes upfront (`BUG-CDR-02`, Master Plan v2 §2.1)
                            if (meta.total_size_bytes as usize) > max_stream_bytes {
                                warn!(
                                    "CDR session '{}' rejected upfront: declared total_size_bytes ({}) exceeds policy max ({})",
                                    session_id, meta.total_size_bytes, max_stream_bytes
                                );
                                let _ = out_tx
                                    .send(Ok(DisarmResponse {
                                        result: Some(disarm_response::Result::Error(DisarmError {
                                            code: "RESOURCE_LIMIT_EXCEEDED".to_string(),
                                            message: format!(
                                                "Declared total_size_bytes ({} bytes) exceeds policy maximum of {} bytes",
                                                meta.total_size_bytes, max_stream_bytes
                                            ),
                                            recoverable: false,
                                        })),
                                    }))
                                    .await;
                                return;
                            }
                            info!(
                                "CDR stream session '{}' initiated for '{}' (declared_format={}, declared_size={})",
                                session_id, file_name, meta.declared_format, meta.total_size_bytes
                            );
                        }
                        Some(disarm_request::Payload::ChunkData(bytes)) => {
                            if raw_buffer.len().saturating_add(bytes.len()) > max_stream_bytes {
                                warn!(
                                    "CDR session '{}' rejected: stream size exceeded {} bytes",
                                    session_id, max_stream_bytes
                                );
                                let _ = out_tx
                                    .send(Ok(DisarmResponse {
                                        result: Some(disarm_response::Result::Error(DisarmError {
                                            code: "RESOURCE_LIMIT_EXCEEDED".to_string(),
                                            message: format!(
                                                "Stream payload exceeds policy maximum of {} bytes",
                                                max_stream_bytes
                                            ),
                                            recoverable: false,
                                        })),
                                    }))
                                    .await;
                                return;
                            }
                            raw_buffer.extend_from_slice(&bytes);
                        }
                        None => {}
                    },
                    Err(e) => {
                        warn!("Error in incoming CDR stream: {}", e);
                        let _ = out_tx
                            .send(Ok(DisarmResponse {
                                result: Some(disarm_response::Result::Error(DisarmError {
                                    code: "STREAM_READ_ERROR".to_string(),
                                    message: e.to_string(),
                                    recoverable: false,
                                })),
                            }))
                            .await;
                        return;
                    }
                }
            }

            if raw_buffer.is_empty() {
                let _ = out_tx
                    .send(Ok(DisarmResponse {
                        result: Some(disarm_response::Result::Error(DisarmError {
                            code: "EMPTY_PAYLOAD".to_string(),
                            message: "Empty payload received by CDR stream".to_string(),
                            recoverable: false,
                        })),
                    }))
                    .await;
                return;
            }

            // 2. Dispatch sanitization strictly to isolated per-file sandboxed worker (`Invariant I3`, `BUG-CDR-07`)
            let permit = match semaphore.acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    let _ = out_tx
                        .send(Err(Status::unavailable("CDR worker semaphore closed")))
                        .await;
                    return;
                }
            };

            let original_size_bytes = raw_buffer.len() as u64;
            let file_name_for_worker = file_name.clone();
            let policy_for_worker = effective_policy.clone();

            let sanitize_result = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let launcher = WorkerLauncher::new();
                launcher.sanitize_isolated(WorkerRequest {
                    file_name: file_name_for_worker,
                    policy: policy_for_worker,
                    raw_bytes: raw_buffer,
                })
            })
            .await;

            // Increment total_processed only after processing completes (`BUG-CDR-01`)
            total_processed.fetch_add(1, Ordering::AcqRel);

            let outcome_result = match sanitize_result {
                Ok(res) => res,
                Err(join_err) => {
                    error!("CDR worker task panicked: {}", join_err);
                    let _ = out_tx
                        .send(Err(Status::internal("CDR worker task panicked")))
                        .await;
                    return;
                }
            };

            // 3. Emit DisarmResponse frames
            match outcome_result {
                Ok(outcome) => {
                    const CHUNK_SIZE: usize = 64 * 1024;
                    for chunk in outcome.clean_bytes.chunks(CHUNK_SIZE) {
                        let resp = DisarmResponse {
                            result: Some(disarm_response::Result::SanitizedChunk(chunk.to_vec())),
                        };
                        if out_tx.send(Ok(resp)).await.is_err() {
                            return;
                        }
                    }

                    let was_modified = outcome.original_sha256 != outcome.sanitized_sha256
                        || !outcome.disarm_report.is_empty();
                    let orig_sha_bytes = hex::decode(&outcome.original_sha256).unwrap_or_default();
                    let san_sha_bytes = hex::decode(&outcome.sanitized_sha256).unwrap_or_default();

                    let summary_elements: Vec<SanitizedElement> = outcome
                        .disarm_report
                        .into_iter()
                        .map(|el| SanitizedElement {
                            element_type: el.element_type,
                            location_path: el.location_path,
                            action_taken: el.action_taken,
                        })
                        .collect();

                    let summary_resp = DisarmResponse {
                        result: Some(disarm_response::Result::Summary(SanitizationSummary {
                            session_id,
                            original_sha256: orig_sha_bytes,
                            sanitized_sha256: san_sha_bytes,
                            original_size_bytes,
                            sanitized_size_bytes: outcome.clean_bytes.len() as u64,
                            sanitized_elements: summary_elements,
                            was_modified,
                            processing_duration_micros: (outcome.processing_time_ms as i64) * 1000,
                        })),
                    };
                    let _ = out_tx.send(Ok(summary_resp)).await;
                }
                Err(err) => {
                    error!("Sanitization failed for session '{}': {}", session_id, err);
                    let err_resp = DisarmResponse {
                        result: Some(disarm_response::Result::Error(DisarmError {
                            code: "DISARM_PROCESSING_FAILED".to_string(),
                            message: err.to_string(),
                            recoverable: false,
                        })),
                    };
                    let _ = out_tx.send(Ok(err_resp)).await;
                }
            }
        });

        let output_stream = ReceiverStream::new(out_rx);
        Ok(Response::new(
            Box::pin(output_stream) as Self::StreamDisarmStream
        ))
    }

    async fn inspect_artifact(
        &self,
        request: Request<InspectRequest>,
    ) -> Result<Response<InspectResponse>, Status> {
        let req = request.into_inner();
        let assessment = tokio::task::spawn_blocking(move || {
            let launcher = WorkerLauncher::new();
            launcher.inspect_isolated(&req.header_bytes, &req.file_name)
        })
        .await
        .map_err(|e| Status::internal(format!("Inspect worker join error: {}", e)))?
        .map_err(|e| Status::internal(format!("Sandboxed inspect worker error: {}", e)))?;

        let proto_format = Self::map_detected_format(assessment.detected_format);

        let response = InspectResponse {
            detected_format: proto_format,
            is_polyglot: assessment.is_malicious_polyglot,
            entropy_score: assessment.entropy_score,
            detected_risk_tags: assessment.risk_tags,
            requires_cdr: proto_format != FileFormatType::FormatUnknown as i32,
        };

        Ok(Response::new(response))
    }

    async fn check_health(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let response = HealthCheckResponse {
            status: "SERVING".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            active_sessions: self.active_sessions_count(),
            total_disarmed_files: self.total_processed_count(),
        };
        Ok(Response::new(response))
    }
}
