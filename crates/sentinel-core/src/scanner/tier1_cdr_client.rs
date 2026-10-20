use sentinel_proto::content_disarm_service_client::ContentDisarmServiceClient;
use sentinel_proto::{
    disarm_request, disarm_response, DisarmMetadata, DisarmPolicy, DisarmRequest, FileFormatType,
    SanitizationSummary,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tracing::{debug, info};

pub struct Tier1CdrClient {
    endpoint: String,
}

impl Tier1CdrClient {
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }

    pub async fn disarm_file(
        &self,
        file_bytes: &[u8],
        file_name: &str,
    ) -> Result<(Vec<u8>, SanitizationSummary), Box<dyn std::error::Error + Send + Sync>> {
        debug!(
            "Connecting to Sentinel CDR gRPC daemon at {} for file '{}'",
            self.endpoint, file_name
        );

        let mut client = ContentDisarmServiceClient::connect(self.endpoint.clone()).await?;

        let (tx, rx) = mpsc::channel(16);
        let request_stream = ReceiverStream::new(rx);

        // 1. Send initial metadata frame
        let metadata = DisarmMetadata {
            session_id: uuid::Uuid::new_v4().to_string(),
            file_name: file_name.to_string(),
            declared_format: FileFormatType::FormatUnknown as i32,
            total_size_bytes: file_bytes.len() as u64,
            policy: Some(DisarmPolicy {
                strip_macros: true,
                strip_javascript: true,
                strip_embedded_files: true,
                strip_external_hyperlinks: true,
                strip_exif_metadata: true,
                truncate_overlay_bytes: true,
                max_recursion_depth: 8,
            }),
        };

        tx.send(DisarmRequest {
            payload: Some(disarm_request::Payload::Metadata(metadata)),
        })
        .await?;

        // 2. Stream chunked file bytes
        const CHUNK_SIZE: usize = 64 * 1024;
        let file_chunks: Vec<_> = file_bytes.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();

        tokio::spawn(async move {
            for chunk in file_chunks {
                let req = DisarmRequest {
                    payload: Some(disarm_request::Payload::ChunkData(chunk)),
                };
                if tx.send(req).await.is_err() {
                    break;
                }
            }
        });

        // 3. Receive sanitized streaming response
        let response = client.stream_disarm(request_stream).await?;
        let mut resp_stream = response.into_inner();

        let mut sanitized_buffer = Vec::new();
        let mut final_summary = None;

        while let Some(resp_result) = resp_stream.next().await {
            let resp = resp_result?;
            match resp.result {
                Some(disarm_response::Result::SanitizedChunk(chunk)) => {
                    sanitized_buffer.extend_from_slice(&chunk);
                }
                Some(disarm_response::Result::Summary(summary)) => {
                    final_summary = Some(summary);
                }
                Some(disarm_response::Result::Error(err)) => {
                    return Err(format!("CDR engine reported error: [{}] {}", err.code, err.message).into());
                }
                None => {}
            }
        }

        let summary = final_summary.ok_or("CDR engine closed stream without returning SanitizationSummary")?;
        info!(
            "CDR disarm completed: original={} bytes, sanitized={} bytes, modified={}",
            summary.original_size_bytes, summary.sanitized_size_bytes, summary.was_modified
        );

        Ok((sanitized_buffer, summary))
    }
}
