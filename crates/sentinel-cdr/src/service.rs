use crate::engine::CdrEngine;
use crate::policy::SanitizationPolicy;
use sentinel_proto::content_disarm_service_server::ContentDisarmService;
use sentinel_proto::{
    disarm_request, disarm_response, DisarmError, DisarmMetadata, DisarmRequest, DisarmResponse,
    FileFormatType, HealthCheckRequest, HealthCheckResponse, InspectRequest, InspectResponse,
    SanitizationSummary, SanitizedElement,
};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::{Request, Response, Status};
use tracing::{error, warn};

pub struct CdrGrpcService {
    engine: Arc<CdrEngine>,
    active_sessions: AtomicU64,
    total_processed: AtomicU64,
}

impl CdrGrpcService {
    pub fn new(policy: SanitizationPolicy) -> Self {
        Self {
            engine: Arc::new(CdrEngine::new(policy)),
            active_sessions: AtomicU64::new(0),
            total_processed: AtomicU64::new(0),
        }
    }
}

#[tonic::async_trait]
impl ContentDisarmService for CdrGrpcService {
    type StreamDisarmStream = Pin<Box<dyn Stream<Item = std::result::Result<DisarmResponse, Status>> + Send + 'static>>;

    async fn stream_disarm(
        &self,
        request: Request<tonic::Streaming<DisarmRequest>>,
    ) -> std::result::Result<Response<Self::StreamDisarmStream>, Status> {
        self.active_sessions.fetch_add(1, Ordering::SeqCst);
        let mut in_stream = request.into_inner();
        let (out_tx, out_rx) = mpsc::channel(32);

        let engine = Arc::clone(&self.engine);

        tokio::spawn(async move {
            let mut file_buffer = Vec::new();
            let mut metadata: Option<DisarmMetadata> = None;

            while let Some(chunk_res) = in_stream.next().await {
                match chunk_res {
                    Ok(req) => match req.payload {
                        Some(disarm_request::Payload::Metadata(meta)) => {
                            metadata = Some(meta);
                        }
                        Some(disarm_request::Payload::ChunkData(bytes)) => {
                            file_buffer.extend_from_slice(&bytes);
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

            let session_id = metadata
                .as_ref()
                .map(|m| m.session_id.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

            // Run sanitization through the engine
            match engine.sanitize(&file_buffer) {
                Ok((sanitized_bytes, report)) => {
                    // 1. Stream the sanitized chunks back
                    const CHUNK_SIZE: usize = 64 * 1024; // 64 KB streaming chunks
                    for chunk in sanitized_bytes.chunks(CHUNK_SIZE) {
                        let resp = DisarmResponse {
                            result: Some(disarm_response::Result::SanitizedChunk(
                                chunk.to_vec(),
                            )),
                        };
                        if out_tx.send(Ok(resp)).await.is_err() {
                            return;
                        }
                    }

                    // 2. Send the final SanitizationSummary
                    let summary_elements = report
                        .stripped_elements
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
                            original_sha256: report.original_sha256.to_vec(),
                            sanitized_sha256: report.sanitized_sha256.to_vec(),
                            original_size_bytes: report.original_size_bytes,
                            sanitized_size_bytes: report.sanitized_size_bytes,
                            sanitized_elements: summary_elements,
                            was_modified: report.was_modified,
                            processing_duration_micros: report.duration_micros as i64,
                        })),
                    };
                    let _ = out_tx.send(Ok(summary_resp)).await;
                }
                Err(err) => {
                    error!("Sanitization failed for session {}: {}", session_id, err);
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

        self.total_processed.fetch_add(1, Ordering::SeqCst);
        self.active_sessions.fetch_sub(1, Ordering::SeqCst);

        let output_stream = ReceiverStream::new(out_rx);
        Ok(Response::new(Box::pin(output_stream) as Self::StreamDisarmStream))
    }

    async fn inspect_artifact(
        &self,
        request: Request<InspectRequest>,
    ) -> std::result::Result<Response<InspectResponse>, Status> {
        let req = request.into_inner();
        let format = CdrEngine::detect_format(&req.header_bytes);

        let proto_format = match format {
            crate::engine::DetectedFormat::Pdf => FileFormatType::FormatPdf,
            crate::engine::DetectedFormat::Docx => FileFormatType::FormatDocx,
            crate::engine::DetectedFormat::Xlsx => FileFormatType::FormatXlsx,
            crate::engine::DetectedFormat::Pptx => FileFormatType::FormatPptx,
            crate::engine::DetectedFormat::Jpeg => FileFormatType::FormatJpeg,
            crate::engine::DetectedFormat::Png => FileFormatType::FormatPng,
            crate::engine::DetectedFormat::WebP => FileFormatType::FormatWebp,
            crate::engine::DetectedFormat::Unknown => FileFormatType::FormatUnknown,
        };

        let response = InspectResponse {
            detected_format: proto_format as i32,
            is_polyglot: false,
            entropy_score: 5.4,
            detected_risk_tags: vec![],
            requires_cdr: proto_format != FileFormatType::FormatUnknown,
        };

        Ok(Response::new(response))
    }

    async fn check_health(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> std::result::Result<Response<HealthCheckResponse>, Status> {
        let response = HealthCheckResponse {
            status: "SERVING".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            total_disarmed_files: self.total_processed.load(Ordering::Relaxed),
        };
        Ok(Response::new(response))
    }
}
