use prost::Message;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;
use tracing::{info, warn};

use sentinel_proto::{
    disarm_request, disarm_response, DisarmError, DisarmMetadata, DisarmRequest, DisarmResponse,
    FileFormatType, InspectRequest, InspectResponse, SanitizationSummary, SanitizedElement,
};
use sentinel_sys::{spawn_sandboxed_worker_process, JobSandboxConfig};

use crate::engine::{DetectedFormat, InspectionAssessment, SanitizationOutcome};
use crate::error::CdrError;
use crate::policy::SanitizationPolicy;
use crate::sanitizers::DisarmReportItem;

const MAX_IPC_FRAME_BYTES: usize = 128 * 1024 * 1024; // 128 MB hard pipe frame ceiling
const FRAME_TAG_DISARM: u8 = 0x01;
const FRAME_TAG_INSPECT: u8 = 0x02;

static ACTIVE_WORKERS: AtomicU64 = AtomicU64::new(0);
static PROCESSED_TOTAL_OK: AtomicU64 = AtomicU64::new(0);
static PROCESSED_TOTAL_ERR: AtomicU64 = AtomicU64::new(0);

/// Process-wide worker concurrency semaphore (`available_parallelism()`, Row 87).
struct WorkerConcurrencyLimiter {
    active: Mutex<usize>,
    cvar: Condvar,
    max_concurrent: usize,
}

impl WorkerConcurrencyLimiter {
    fn global() -> &'static Self {
        static LIMITER: OnceLock<WorkerConcurrencyLimiter> = OnceLock::new();
        LIMITER.get_or_init(|| {
            let max_concurrent = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .max(1);
            Self {
                active: Mutex::new(0),
                cvar: Condvar::new(),
                max_concurrent,
            }
        })
    }

    fn acquire(&'static self) -> ConcurrencyPermit {
        let mut count = self.active.lock().unwrap_or_else(|e| e.into_inner());
        while *count >= self.max_concurrent {
            count = self.cvar.wait(count).unwrap_or_else(|e| e.into_inner());
        }
        *count += 1;
        ACTIVE_WORKERS.fetch_add(1, Ordering::AcqRel);
        ConcurrencyPermit { limiter: self }
    }
}

/// RAII guard tracking `active_workers` and releasing a concurrency slot on worker exit,
/// including timeouts and kills (`Rows 87, 104`).
struct ConcurrencyPermit {
    limiter: &'static WorkerConcurrencyLimiter,
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        ACTIVE_WORKERS.fetch_sub(1, Ordering::AcqRel);
        let mut count = self
            .limiter
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *count = count.saturating_sub(1);
        self.limiter.cvar.notify_one();
    }
}

pub fn map_detected_format_to_proto(fmt: DetectedFormat) -> i32 {
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

pub fn map_proto_to_detected_format(proto_val: i32) -> DetectedFormat {
    match FileFormatType::try_from(proto_val).unwrap_or(FileFormatType::FormatUnknown) {
        FileFormatType::FormatPdf => DetectedFormat::Pdf,
        FileFormatType::FormatDocx => DetectedFormat::Docx,
        FileFormatType::FormatXlsx => DetectedFormat::Xlsx,
        FileFormatType::FormatPptx => DetectedFormat::Pptx,
        FileFormatType::FormatJpeg => DetectedFormat::Jpeg,
        FileFormatType::FormatPng => DetectedFormat::Png,
        FileFormatType::FormatWebp => DetectedFormat::WebP,
        FileFormatType::FormatSvg => DetectedFormat::Svg,
        FileFormatType::FormatOle2 => DetectedFormat::Ole2,
        FileFormatType::FormatTxt => DetectedFormat::PlainText,
        FileFormatType::FormatCsv => DetectedFormat::Csv,
        FileFormatType::FormatArchiveZip => DetectedFormat::ArchiveZip,
        FileFormatType::FormatUnknown => DetectedFormat::Unknown,
    }
}

fn write_prost_frame<W: Write, M: Message>(writer: &mut W, msg: &M) -> std::io::Result<()> {
    let encoded = msg.encode_to_vec();
    if encoded.len() > MAX_IPC_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Protobuf frame exceeds MAX_IPC_FRAME_BYTES",
        ));
    }
    let len = encoded.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&encoded)?;
    Ok(())
}

fn read_prost_frame<R: Read, M: Message + Default>(reader: &mut R) -> std::io::Result<M> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_IPC_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Incoming protobuf frame length {} exceeds cap", len),
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    M::decode(&buf[..]).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub file_name: String,
    pub policy: SanitizationPolicy,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub success: bool,
    pub outcome: Option<SanitizationOutcome>,
    pub error: Option<String>,
}

/// Discriminated worker pipe command supporting both `DisarmRequest` (`0x01`) and
/// `InspectRequest` (`0x02`) length-prefixed `prost::Message` frames (`Row 30, 103`).
#[derive(Debug, Clone)]
pub enum WorkerCommand {
    Disarm(WorkerRequest),
    Inspect {
        file_name: String,
        raw_bytes: Vec<u8>,
    },
}

impl WorkerCommand {
    pub fn read_framed<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            FRAME_TAG_DISARM => {
                let req = WorkerRequest::read_framed_body(&mut reader)?;
                Ok(WorkerCommand::Disarm(req))
            }
            FRAME_TAG_INSPECT => {
                let proto_req: InspectRequest = read_prost_frame(&mut reader)?;
                Ok(WorkerCommand::Inspect {
                    file_name: proto_req.file_name,
                    raw_bytes: proto_req.header_bytes,
                })
            }
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown worker protobuf frame tag: 0x{:02X}", other),
            )),
        }
    }
}

impl WorkerRequest {
    /// Writes a length-prefixed `prost::Message` (`DisarmRequest` metadata + chunk) stream (`Row 30`).
    pub fn write_framed<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&[FRAME_TAG_DISARM])?;
        let meta_req = DisarmRequest {
            payload: Some(disarm_request::Payload::Metadata(DisarmMetadata {
                session_id: uuid::Uuid::new_v4().to_string(),
                file_name: self.file_name.clone(),
                declared_format: FileFormatType::FormatUnknown as i32,
                total_size_bytes: self.raw_bytes.len() as u64,
                policy: Some(self.policy.to_proto()),
            })),
        };
        let chunk_req = DisarmRequest {
            payload: Some(disarm_request::Payload::ChunkData(self.raw_bytes.clone())),
        };
        write_prost_frame(&mut writer, &meta_req)?;
        write_prost_frame(&mut writer, &chunk_req)?;
        writer.flush()?;
        Ok(())
    }

    pub fn read_framed<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        if tag[0] != FRAME_TAG_DISARM {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Expected FRAME_TAG_DISARM (0x01), got 0x{:02X}", tag[0]),
            ));
        }
        Self::read_framed_body(&mut reader)
    }

    fn read_framed_body<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let meta_frame: DisarmRequest = read_prost_frame(reader)?;
        let chunk_frame: DisarmRequest = read_prost_frame(reader)?;

        let (file_name, policy, declared_size) = match meta_frame.payload {
            Some(disarm_request::Payload::Metadata(meta)) => {
                let pol = match meta.policy {
                    Some(p) => SanitizationPolicy::from_worker_proto(p),
                    None => SanitizationPolicy::default(),
                };
                (meta.file_name, pol, meta.total_size_bytes as usize)
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "First DisarmRequest frame must carry DisarmMetadata",
                ));
            }
        };

        if declared_size > MAX_IPC_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Declared total_size_bytes exceeds worker frame cap",
            ));
        }

        let raw_bytes = match chunk_frame.payload {
            Some(disarm_request::Payload::ChunkData(bytes)) => bytes,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Second DisarmRequest frame must carry ChunkData",
                ));
            }
        };

        Ok(Self {
            file_name,
            policy,
            raw_bytes,
        })
    }
}

impl WorkerResponse {
    /// Writes length-prefixed `prost::Message` (`DisarmResponse`) frames (`Row 30`).
    pub fn write_framed<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&[FRAME_TAG_DISARM])?;
        if self.success {
            if let Some(ref outcome) = self.outcome {
                let chunk_resp = DisarmResponse {
                    result: Some(disarm_response::Result::SanitizedChunk(
                        outcome.clean_bytes.clone(),
                    )),
                };
                let orig_sha = hex::decode(&outcome.original_sha256).unwrap_or_default();
                let san_sha = hex::decode(&outcome.sanitized_sha256).unwrap_or_default();
                let fmt_code = map_detected_format_to_proto(outcome.detected_format);
                let summary_resp = DisarmResponse {
                    result: Some(disarm_response::Result::Summary(SanitizationSummary {
                        session_id: format!("FMT:{}", fmt_code),
                        original_sha256: orig_sha,
                        sanitized_sha256: san_sha,
                        original_size_bytes: 0,
                        sanitized_size_bytes: outcome.clean_bytes.len() as u64,
                        sanitized_elements: outcome
                            .disarm_report
                            .iter()
                            .map(|r| SanitizedElement {
                                element_type: r.element_type.clone(),
                                location_path: r.location_path.clone(),
                                action_taken: r.action_taken.clone(),
                            })
                            .collect(),
                        was_modified: outcome.original_sha256 != outcome.sanitized_sha256
                            || !outcome.disarm_report.is_empty(),
                        processing_duration_micros: (outcome.processing_time_ms as i64) * 1000,
                    })),
                };
                write_prost_frame(&mut writer, &chunk_resp)?;
                write_prost_frame(&mut writer, &summary_resp)?;
                writer.flush()?;
                return Ok(());
            }
        }

        let err_resp = DisarmResponse {
            result: Some(disarm_response::Result::Error(DisarmError {
                code: "CDR_WORKER_ERROR".to_string(),
                message: self
                    .error
                    .clone()
                    .unwrap_or_else(|| "CDR worker rejected artifact".to_string()),
                recoverable: false,
            })),
        };
        write_prost_frame(&mut writer, &err_resp)?;
        writer.flush()?;
        Ok(())
    }

    pub fn read_framed<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        if tag[0] != FRAME_TAG_DISARM {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Expected FRAME_TAG_DISARM (0x01), got 0x{:02X}", tag[0]),
            ));
        }

        let first_frame: DisarmResponse = read_prost_frame(&mut reader)?;
        match first_frame.result {
            Some(disarm_response::Result::Error(err)) => Ok(Self {
                success: false,
                outcome: None,
                error: Some(err.message),
            }),
            Some(disarm_response::Result::SanitizedChunk(clean_bytes)) => {
                let second_frame: DisarmResponse = read_prost_frame(&mut reader)?;
                match second_frame.result {
                    Some(disarm_response::Result::Summary(summary)) => {
                        let fmt_code = summary
                            .session_id
                            .strip_prefix("FMT:")
                            .and_then(|s| s.parse::<i32>().ok())
                            .unwrap_or(FileFormatType::FormatUnknown as i32);
                        let detected_format = map_proto_to_detected_format(fmt_code);
                        let disarm_report = summary
                            .sanitized_elements
                            .into_iter()
                            .map(|el| {
                                DisarmReportItem::new(
                                    el.element_type,
                                    el.location_path,
                                    el.action_taken,
                                )
                            })
                            .collect();
                        Ok(Self {
                            success: true,
                            outcome: Some(SanitizationOutcome {
                                clean_bytes,
                                original_sha256: hex::encode(&summary.original_sha256),
                                sanitized_sha256: hex::encode(&summary.sanitized_sha256),
                                detected_format,
                                disarm_report,
                                processing_time_ms: (summary.processing_duration_micros.max(0)
                                    as u64)
                                    / 1000,
                            }),
                            error: None,
                        })
                    }
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Expected SanitizationSummary frame after SanitizedChunk",
                    )),
                }
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unexpected first DisarmResponse variant from worker",
            )),
        }
    }
}

pub fn write_inspect_request_framed<W: Write>(
    mut writer: W,
    file_name: &str,
    raw_bytes: &[u8],
) -> std::io::Result<()> {
    writer.write_all(&[FRAME_TAG_INSPECT])?;
    let req = InspectRequest {
        header_bytes: raw_bytes.to_vec(),
        file_name: file_name.to_string(),
        file_size_bytes: raw_bytes.len() as u64,
    };
    write_prost_frame(&mut writer, &req)?;
    writer.flush()
}

pub fn write_inspect_response_framed<W: Write>(
    mut writer: W,
    assessment: &InspectionAssessment,
) -> std::io::Result<()> {
    writer.write_all(&[FRAME_TAG_INSPECT])?;
    let proto_fmt = map_detected_format_to_proto(assessment.detected_format);
    let resp = InspectResponse {
        detected_format: proto_fmt,
        is_polyglot: assessment.is_malicious_polyglot,
        entropy_score: assessment.entropy_score,
        detected_risk_tags: assessment.risk_tags.clone(),
        requires_cdr: proto_fmt != FileFormatType::FormatUnknown as i32,
    };
    write_prost_frame(&mut writer, &resp)?;
    writer.flush()
}

pub fn read_inspect_response_framed<R: Read>(
    mut reader: R,
) -> std::io::Result<InspectionAssessment> {
    let mut tag = [0u8; 1];
    reader.read_exact(&mut tag)?;
    if tag[0] != FRAME_TAG_INSPECT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Expected FRAME_TAG_INSPECT (0x02), got 0x{:02X}", tag[0]),
        ));
    }
    let resp: InspectResponse = read_prost_frame(&mut reader)?;
    let detected_format = map_proto_to_detected_format(resp.detected_format);
    Ok(InspectionAssessment {
        is_malicious_polyglot: resp.is_polyglot,
        detected_format,
        true_mime_type: detected_format.as_mime_str().to_string(),
        entropy_score: resp.entropy_score,
        risk_tags: resp.detected_risk_tags,
    })
}

/// Ephemeral Per-File Sandboxed CDR Worker Launcher (`BUG-CDR-10`, Phase 2.1, Invariant I3)
///
/// Spawns one isolated `sentinel-cdr-worker` child process per file using `CreateProcessW`
/// with `CREATE_SUSPENDED` + `STARTUPINFOEXW` mitigations and a 256 MB Job Object assigned
/// before `ResumeThread`. Enforces a 30-second parent deadline covering both `stdin` write
/// and `stdout` read, with zero in-process parsing fallback (`Invariant I3`).
pub struct WorkerLauncher {
    worker_bin: Option<PathBuf>,
    wall_clock_timeout: Duration,
    sandbox_config: JobSandboxConfig,
}

impl Default for WorkerLauncher {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerLauncher {
    pub fn new() -> Self {
        let worker_bin = Self::locate_worker_binary();
        Self {
            worker_bin,
            wall_clock_timeout: Duration::from_secs(30), // 30s default deadline (Master Plan v2 §2.1, Row 98)
            sandbox_config: JobSandboxConfig::default(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.wall_clock_timeout = timeout;
        self
    }

    pub fn with_sandbox_config(mut self, config: JobSandboxConfig) -> Self {
        self.sandbox_config = config;
        self
    }

    pub fn active_workers_count() -> u64 {
        ACTIVE_WORKERS.load(Ordering::Acquire)
    }

    pub fn processed_ok_count() -> u64 {
        PROCESSED_TOTAL_OK.load(Ordering::Acquire)
    }

    pub fn processed_err_count() -> u64 {
        PROCESSED_TOTAL_ERR.load(Ordering::Acquire)
    }

    pub fn locate_worker_binary() -> Option<PathBuf> {
        let exe_name = if cfg!(windows) {
            "sentinel-cdr-worker.exe"
        } else {
            "sentinel-cdr-worker"
        };

        if let Some(env_bin) = std::env::var_os("CARGO_BIN_EXE_sentinel-cdr-worker") {
            let p = PathBuf::from(env_bin);
            if p.exists() {
                return Some(p);
            }
        }
        if let Some(env_bin) = std::env::var_os("SENTINEL_CDR_WORKER_BIN") {
            let p = PathBuf::from(env_bin);
            if p.exists() {
                return Some(p);
            }
        }

        if let Ok(current_exe) = std::env::current_exe() {
            if let Some(dir) = current_exe.parent() {
                let candidate = dir.join(exe_name);
                if candidate.exists() {
                    return Some(candidate);
                }
                if let Some(parent_dir) = dir.parent() {
                    let parent_candidate = parent_dir.join(exe_name);
                    static ENSURE_BUILT: OnceLock<()> = OnceLock::new();
                    ENSURE_BUILT.get_or_init(|| {
                        let needs_build = match (
                            current_exe.metadata().and_then(|m| m.modified()),
                            parent_candidate.metadata().and_then(|m| m.modified()),
                        ) {
                            (Ok(test_mtime), Ok(worker_mtime)) => worker_mtime < test_mtime,
                            _ => !parent_candidate.exists(),
                        };
                        if needs_build {
                            let _ = std::process::Command::new("cargo")
                                .args(["build", "--offline", "--bin", "sentinel-cdr-worker"])
                                .stdout(std::process::Stdio::null())
                                .stderr(std::process::Stdio::null())
                                .status();
                        }
                    });
                    if parent_candidate.exists() {
                        return Some(parent_candidate);
                    }
                }
            }
        }
        None
    }

    /// Executes CDR sanitization strictly inside an isolated per-file worker process (`Invariant I3`).
    /// Never falls back to in-process parsing; fails closed with `CdrError::SandboxFailure` if the
    /// sandboxed worker cannot be spawned.
    pub fn sanitize_isolated(
        &self,
        request: WorkerRequest,
    ) -> Result<SanitizationOutcome, CdrError> {
        let bin_path = self.worker_bin.as_ref().ok_or_else(|| {
            PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
            CdrError::SandboxFailure(
                "CDR_WORKER_FAILED: sentinel-cdr-worker binary not found; refusing in-process parsing (Invariant I3)"
                    .to_string(),
            )
        })?;
        if !bin_path.exists() {
            PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
            return Err(CdrError::SandboxFailure(format!(
                "CDR_WORKER_FAILED: sentinel-cdr-worker binary missing at {}; refusing in-process parsing (Invariant I3)",
                bin_path.display()
            )));
        }

        self.run_child_disarm(bin_path, request)
    }

    /// Executes forensic artifact inspection (`InspectRequest` -> `InspectResponse`) strictly
    /// inside an isolated per-file sandboxed worker process (`Invariant I3`, Row 8, 103).
    pub fn inspect_isolated(
        &self,
        raw_bytes: &[u8],
        file_name: &str,
    ) -> Result<InspectionAssessment, CdrError> {
        let bin_path = self.worker_bin.as_ref().ok_or_else(|| {
            PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
            CdrError::SandboxFailure(
                "CDR_WORKER_FAILED: sentinel-cdr-worker binary not found; refusing in-process inspection (Invariant I3)"
                    .to_string(),
            )
        })?;
        if !bin_path.exists() {
            PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
            return Err(CdrError::SandboxFailure(format!(
                "CDR_WORKER_FAILED: sentinel-cdr-worker binary missing at {}; refusing in-process inspection (Invariant I3)",
                bin_path.display()
            )));
        }

        self.run_child_inspect(bin_path, raw_bytes, file_name)
    }

    fn run_child_disarm(
        &self,
        bin_path: &Path,
        request: WorkerRequest,
    ) -> Result<SanitizationOutcome, CdrError> {
        let _permit = WorkerConcurrencyLimiter::global().acquire();

        let mut child =
            spawn_sandboxed_worker_process(bin_path, &self.sandbox_config).map_err(|e| {
                PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
                CdrError::SandboxFailure(format!(
                    "CDR_WORKER_FAILED: failed spawning sandboxed CDR worker: {}",
                    e
                ))
            })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            let _ = child.kill_and_wait();
            PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
            CdrError::SandboxFailure("CDR worker stdin pipe missing".to_string())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            let _ = child.kill_and_wait();
            PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
            CdrError::SandboxFailure("CDR worker stdout pipe missing".to_string())
        })?;

        let timeout = self.wall_clock_timeout;
        let file_name_log = request.file_name.clone();
        let req_for_io = request;

        // Run BOTH stdin write and stdout read under the single 30-second parent deadline (`Row 94, 99`)
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let write_handle = std::thread::spawn(move || req_for_io.write_framed(stdin));
            let read_res = WorkerResponse::read_framed(stdout);
            let write_res = write_handle.join().unwrap_or_else(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "Worker stdin writer panicked",
                ))
            });
            let _ = tx.send((write_res, read_res));
        });

        let response = match rx.recv_timeout(timeout) {
            Ok((_write_res, Ok(resp))) => resp,
            Ok((Err(we), Err(re))) => {
                let exit_code = child.kill_and_wait().ok().flatten();
                PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
                return Err(CdrError::ResourceLimitExceeded(format!(
                    "CDR_WORKER_FAILED: worker terminated during pipe I/O (exit={:?}, write_err={}, read_err={})",
                    exit_code, we, re
                )));
            }
            Ok((Ok(()), Err(re))) => {
                let exit_code = child.kill_and_wait().ok().flatten();
                PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
                return Err(CdrError::ResourceLimitExceeded(format!(
                    "CDR_WORKER_FAILED: worker exited or exceeded 256 MB Job Object memory cap (exit={:?}, err={})",
                    exit_code, re
                )));
            }
            Err(_) => {
                warn!(
                    "CDR_WORKER_FAILED: killing CDR worker (pid={}) after exceeding {:?} wall-clock deadline",
                    child.pid, timeout
                );
                let _ = child.kill_and_wait();
                PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
                return Err(CdrError::WorkerTimeout(format!(
                    "CDR_WORKER_FAILED: worker exceeded wall-clock timeout ({:?})",
                    timeout
                )));
            }
        };

        let _ = child.wait();

        if response.success {
            if let Some(outcome) = response.outcome {
                PROCESSED_TOTAL_OK.fetch_add(1, Ordering::AcqRel);
                info!(
                    "Sandboxed CDR worker (pid={}) completed file '{}' ({} ms)",
                    child.pid, file_name_log, outcome.processing_time_ms
                );
                return Ok(outcome);
            }
        }

        PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
        let err_msg = response
            .error
            .unwrap_or_else(|| "CDR worker rejected artifact".to_string());
        if err_msg.contains("Unsupported file format") {
            return Err(CdrError::UnsupportedFormat(err_msg));
        }
        if err_msg.contains("Invalid format structure") {
            return Err(CdrError::InvalidFormat(err_msg));
        }
        if err_msg.contains("resource limit exceeded") || err_msg.contains("budget") {
            return Err(CdrError::ResourceLimitExceeded(err_msg));
        }
        if err_msg.contains("CDR_OUTPUT_REJECTED") {
            return Err(CdrError::OutputRejected(err_msg));
        }
        Err(CdrError::ParserCorruption(err_msg))
    }

    fn run_child_inspect(
        &self,
        bin_path: &Path,
        raw_bytes: &[u8],
        file_name: &str,
    ) -> Result<InspectionAssessment, CdrError> {
        let _permit = WorkerConcurrencyLimiter::global().acquire();

        let mut child =
            spawn_sandboxed_worker_process(bin_path, &self.sandbox_config).map_err(|e| {
                PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
                CdrError::SandboxFailure(format!(
                    "CDR_WORKER_FAILED: failed spawning sandboxed CDR worker for inspect: {}",
                    e
                ))
            })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            let _ = child.kill_and_wait();
            PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
            CdrError::SandboxFailure("CDR worker stdin pipe missing".to_string())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            let _ = child.kill_and_wait();
            PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
            CdrError::SandboxFailure("CDR worker stdout pipe missing".to_string())
        })?;

        let timeout = self.wall_clock_timeout;
        let payload = raw_bytes.to_vec();
        let fname = file_name.to_string();

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let write_handle =
                std::thread::spawn(move || write_inspect_request_framed(stdin, &fname, &payload));
            let read_res = read_inspect_response_framed(stdout);
            let write_res = write_handle.join().unwrap_or_else(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "Worker inspect stdin writer panicked",
                ))
            });
            let _ = tx.send((write_res, read_res));
        });

        match rx.recv_timeout(timeout) {
            Ok((_w, Ok(assessment))) => {
                let _ = child.wait();
                PROCESSED_TOTAL_OK.fetch_add(1, Ordering::AcqRel);
                Ok(assessment)
            }
            Ok((w, Err(re))) => {
                let exit_code = child.kill_and_wait().ok().flatten();
                PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
                Err(CdrError::ParserCorruption(format!(
                    "CDR_WORKER_FAILED: inspect worker failed (exit={:?}, write={:?}, read={})",
                    exit_code,
                    w.err(),
                    re
                )))
            }
            Err(_) => {
                let _ = child.kill_and_wait();
                PROCESSED_TOTAL_ERR.fetch_add(1, Ordering::AcqRel);
                Err(CdrError::WorkerTimeout(format!(
                    "CDR_WORKER_FAILED: inspect worker exceeded wall-clock timeout ({:?})",
                    timeout
                )))
            }
        }
    }
}
