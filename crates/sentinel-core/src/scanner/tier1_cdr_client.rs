use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use uuid::Uuid;

use sentinel_cdr::engine::InspectionAssessment;
use sentinel_cdr::{SanitizationPolicy, WorkerLauncher, WorkerRequest};
use sentinel_proto::SanitizationSummary;
use sentinel_sys::{write_mark_of_the_web, DEFAULT_NAMED_PIPE_ENDPOINT};

#[derive(Debug, Clone)]
pub struct CdrClientConfig {
    pub ipc_pipe_endpoint: String,
    pub chunk_size_bytes: usize,
    pub use_sandboxed_pipe_worker: bool,
}

impl Default for CdrClientConfig {
    fn default() -> Self {
        Self {
            ipc_pipe_endpoint: DEFAULT_NAMED_PIPE_ENDPOINT.to_string(),
            chunk_size_bytes: 64 * 1024,
            use_sandboxed_pipe_worker: true,
        }
    }
}

/// Tier-1 Content Disarm & Reconstruction (CDR) Client (`BUG-CDR-03`, `BUG-CDR-10`, Phase 2.1, Invariant I3)
///
/// Retires all TCP `127.0.0.1:50051` client connections (`Rows 25, 26, 106`) and dispatches
/// every file strictly through the ephemeral per-file sandboxed pipe worker (`WorkerLauncher`)
/// with a 128 MB decompressed budget inside the 256 MB OS Job Object memory cap.
pub struct Tier1CdrClient {
    config: CdrClientConfig,
}

impl Tier1CdrClient {
    pub fn new(config: CdrClientConfig) -> Self {
        Self { config }
    }

    pub fn ipc_endpoint(&self) -> &str {
        &self.config.ipc_pipe_endpoint
    }

    pub async fn disarm_file(
        &self,
        source_path: &Path,
        dest_path: &Path,
    ) -> Result<SanitizationSummary, String> {
        self.disarm_via_sandboxed_worker(source_path, dest_path)
            .await
    }

    pub async fn inspect_file(&self, source_path: &Path) -> Result<InspectionAssessment, String> {
        let src = source_path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let mut raw_bytes = Vec::new();
            File::open(&src)
                .map_err(|e| format!("Failed opening source file for CDR inspect: {e}"))?
                .read_to_end(&mut raw_bytes)
                .map_err(|e| format!("Failed reading source file for CDR inspect: {e}"))?;

            let file_name = src
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown.bin")
                .to_string();

            let launcher = WorkerLauncher::new();
            launcher
                .inspect_isolated(&raw_bytes, &file_name)
                .map_err(|e| format!("Sandboxed CDR worker inspection failed: {e}"))
        })
        .await
        .map_err(|e| format!("CDR inspect worker task join error: {e}"))?
    }

    async fn disarm_via_sandboxed_worker(
        &self,
        source_path: &Path,
        dest_path: &Path,
    ) -> Result<SanitizationSummary, String> {
        let src = source_path.to_path_buf();
        let dst = dest_path.to_path_buf();

        tokio::task::spawn_blocking(move || {
            let mut raw_bytes = Vec::new();
            File::open(&src)
                .map_err(|e| format!("Failed opening source file for CDR: {e}"))?
                .read_to_end(&mut raw_bytes)
                .map_err(|e| format!("Failed reading source file for CDR: {e}"))?;

            let original_size_bytes = raw_bytes.len() as u64;
            let file_name = src
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown.bin")
                .to_string();

            let launcher = WorkerLauncher::new();
            let outcome = launcher
                .sanitize_isolated(WorkerRequest {
                    file_name,
                    policy: SanitizationPolicy::default(),
                    raw_bytes,
                })
                .map_err(|e| format!("Sandboxed CDR worker rejected file: {e}"))?;

            if let Some(parent) = dst.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        format!("Failed creating destination parent directory for CDR output: {e}")
                    })?;
                }
            }
            let mut out_file = File::create(&dst)
                .map_err(|e| format!("Failed creating destination file for CDR output: {e}"))?;
            out_file
                .write_all(&outcome.clean_bytes)
                .map_err(|e| format!("Failed writing disarmed output: {e}"))?;
            out_file
                .sync_all()
                .map_err(|e| format!("Failed syncing disarmed output: {e}"))?;
            drop(out_file);

            write_mark_of_the_web(&dst, 3)
                .map_err(|e| format!("Failed applying Mark-of-the-Web to CDR output: {e}"))?;

            let orig_sha = hex::decode(&outcome.original_sha256).unwrap_or_default();
            let san_sha = hex::decode(&outcome.sanitized_sha256).unwrap_or_default();
            let sanitized_size_bytes = outcome.clean_bytes.len() as u64;
            let was_modified = outcome.original_sha256 != outcome.sanitized_sha256
                || !outcome.disarm_report.is_empty();

            let sanitized_elements = outcome
                .disarm_report
                .into_iter()
                .map(|r| sentinel_proto::SanitizedElement {
                    element_type: r.element_type,
                    location_path: r.location_path,
                    action_taken: r.action_taken,
                })
                .collect();

            Ok(SanitizationSummary {
                session_id: Uuid::new_v4().to_string(),
                original_sha256: orig_sha,
                sanitized_sha256: san_sha,
                original_size_bytes,
                sanitized_size_bytes,
                sanitized_elements,
                was_modified,
                processing_duration_micros: (outcome.processing_time_ms as i64) * 1000,
            })
        })
        .await
        .map_err(|e| format!("CDR worker task join error: {e}"))?
    }
}
